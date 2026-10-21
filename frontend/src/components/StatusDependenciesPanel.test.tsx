// The Status page's dependency block: Security Onion, Elasticsearch and the
// model gateway, each with its state, the reason in plain words and a link to
// the connection settings (H1-D14, R5-I4).
//
// The page showed no dependency state at all, so an operator who opened Status
// during an outage read green analytics rows and no word about the grid. The
// assertions below pin the rule that matters most here: a read that failed, or
// a leg the server did not report, reads "unknown". It never reads "up". The
// last test plants that failure on the poll path, the path a plain useAsync
// would MISS: a background failure keeps the last-good data on screen.
import { act, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHealth: vi.fn(),
}));

import { getHealth, type Health } from '../lib/api';
import { StatusDependenciesPanel } from './StatusDependenciesPanel';

const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

// The wire shape: `state` and `elapsed_ms` ride on each leg, and the probe
// time rides on the envelope. The TS type names neither, so the fixture is
// cast the way the live JSON arrives.
const ALL_UP = {
  es: { ok: true, detail: 'so, ES 9.3.7. logs-* is readable.', state: 'ok', elapsed_ms: 39 },
  llm: { ok: true, detail: '200 OK. 22 models.', state: 'ok', elapsed_ms: 26 },
  so: { ok: true, detail: 'https://so.example: /api/info 200 OK', state: 'ok', elapsed_ms: 107 },
  pcap: null,
  checked_at: iso(20_000),
  age_s: 20,
} as unknown as Health;

const mount = () =>
  render(
    <MemoryRouter>
      <StatusDependenciesPanel />
    </MemoryRouter>,
  );

function row(name: string): HTMLElement {
  const el = screen
    .getAllByTestId('status-dependency')
    .find((r) => within(r).queryByText(name, { selector: '[data-part="name"]' }));
  if (!el) throw new Error(`no dependency row named ${name}`);
  return el;
}

beforeEach(() => {
  vi.mocked(getHealth).mockReset().mockResolvedValue(ALL_UP);
});

describe('StatusDependenciesPanel', () => {
  it('lists the three dependencies in a fixed order, each up with its answer time', async () => {
    mount();
    await screen.findAllByTestId('status-dependency');
    const names = screen
      .getAllByTestId('status-dependency')
      .map((r) => within(r).getByText(/./, { selector: '[data-part="name"]' }).textContent);
    expect(names).toEqual(['Security Onion', 'Elasticsearch', 'Model gateway']);
    expect(within(row('Elasticsearch')).getByText('up')).toBeInTheDocument();
    expect(within(row('Elasticsearch')).getByText('It answered in 39 ms.')).toBeInTheDocument();
    expect(within(row('Model gateway')).getByText('It answered in 26 ms.')).toBeInTheDocument();
  });

  it('links each row to the connection settings by the section id', async () => {
    mount();
    await screen.findAllByTestId('status-dependency');
    for (const name of ['Security Onion', 'Elasticsearch', 'Model gateway']) {
      const link = within(row(name)).getByRole('link');
      expect(link).toHaveAttribute('href', '/config#danger-zone');
      expect(link).toHaveAccessibleName(`Open the ${name} connection settings`);
    }
  });

  it('names each failure in plain words, and keeps the probe sentence beside it', async () => {
    vi.mocked(getHealth).mockResolvedValue({
      ...ALL_UP,
      es: {
        ok: false,
        kind: 'refused',
        state: 'down',
        detail: 'the grid could not be reached: connection refused',
      },
      llm: {
        ok: false,
        kind: 'slow',
        state: 'slow',
        detail: 'Model gateway answered the probe in 4.1 s. The budget is 5 s.',
      },
      so: {
        ok: false,
        state: 'down',
        detail: 'https://so.example: /api/info answered HTTP 401.',
      },
    } as unknown as Health);
    mount();
    await screen.findAllByTestId('status-dependency');
    const es = row('Elasticsearch');
    expect(within(es).getByText('down')).toBeInTheDocument();
    expect(within(es).getByText('soc-ai cannot connect to it.')).toBeInTheDocument();
    expect(within(es).getByText(/connection refused/)).toBeInTheDocument();
    const llm = row('Model gateway');
    expect(within(llm).getByText('slow')).toBeInTheDocument();
    expect(within(llm).getByText('It answers slowly. A result can arrive late.')).toBeInTheDocument();
    // An unclassified failure still reads down, with the probe's own sentence.
    const so = row('Security Onion');
    expect(within(so).getByText('down')).toBeInTheDocument();
    expect(within(so).getByText('The health check failed.')).toBeInTheDocument();
    expect(within(so).getByText(/answered HTTP 401/)).toBeInTheDocument();
  });

  it('a leg that ran out of its budget reads down, though the wire state is slow', async () => {
    // _bounded_probe marks a timeout state "slow" with kind "timeout", and its
    // own detail says soc-ai treats it as down.
    vi.mocked(getHealth).mockResolvedValue({
      ...ALL_UP,
      es: { ok: false, kind: 'timeout', state: 'slow', detail: 'Elasticsearch did not answer the probe in 5 s.' },
    } as unknown as Health);
    mount();
    await screen.findAllByTestId('status-dependency');
    expect(within(row('Elasticsearch')).getByText('down')).toBeInTheDocument();
    expect(within(row('Elasticsearch')).getByText('It did not answer in time.')).toBeInTheDocument();
  });

  it('a failed read shows every dependency as unknown, never up', async () => {
    vi.mocked(getHealth).mockRejectedValue(new Error('502'));
    mount();
    const rows = await screen.findAllByTestId('status-dependency');
    expect(rows).toHaveLength(3);
    for (const r of rows) {
      expect(within(r).getByText('unknown')).toBeInTheDocument();
      expect(within(r).queryByText('up')).toBeNull();
      expect(within(r).getByText('soc-ai could not read the health check.')).toBeInTheDocument();
    }
  });

  it('a leg an older server does not report reads unknown, not up', async () => {
    const { so: _so, ...noSo } = ALL_UP as unknown as Record<string, unknown>;
    vi.mocked(getHealth).mockResolvedValue(noSo as unknown as Health);
    mount();
    await screen.findAllByTestId('status-dependency');
    const so = row('Security Onion');
    expect(within(so).getByText('unknown')).toBeInTheDocument();
    expect(within(so).getByText('This server does not report it.')).toBeInTheDocument();
    expect(within(row('Elasticsearch')).getByText('up')).toBeInTheDocument();
  });

  it('says when the last health check ran, from the probe time', async () => {
    mount();
    expect(await screen.findByText(/the last health check ran/i)).toHaveTextContent(
      'The last health check ran less than a minute ago.',
    );
  });
});

describe('StatusDependenciesPanel poll', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('reads on the 5-minute tick, and a failed poll turns an up row to unknown', async () => {
    mount();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(getHealth).toHaveBeenCalledTimes(1);
    expect(within(row('Elasticsearch')).getByText('up')).toBeInTheDocument();

    vi.mocked(getHealth).mockRejectedValue(new Error('timeout'));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(299_000);
    });
    expect(getHealth).toHaveBeenCalledTimes(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });
    expect(getHealth).toHaveBeenCalledTimes(2);
    // The last-good "up" must not stand over a read that failed.
    expect(within(row('Elasticsearch')).getByText('unknown')).toBeInTheDocument();
    expect(screen.queryByText('up')).toBeNull();
  });
});
