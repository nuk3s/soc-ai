// The Data sources panel showed an 88-day-old blocklist as a green "Active"
// row and an absent MaxMind file as "Not refreshed" (dogfood 2026-10-19,
// H1-D11, H1 STE item 33). The backend now judges each local feed with the
// doctor's freshness rule and sends the result as `state`. The panel shows that
// state. The notes and the intro render through HelpText, so a backtick span is
// code and "Settings > <Section>" is a link (R5-D17, R5-D18, R5-D21).
import { cleanup, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DataSource } from '../lib/api';

const getDataSourcesMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getDataSources: getDataSourcesMock,
}));

import { DataSourcesPanel } from './DataSourcesPanel';

type Row = DataSource & { state?: string };

function source(over: Partial<Row>): Row {
  return {
    id: 'blocklists',
    name: 'Blocklists (URLhaus / Feodo / Tor / Spamhaus)',
    category: 'Local feed',
    egress: 'none',
    enabled: true,
    present: true,
    last_refreshed: new Date(Date.now() - 88 * 86_400_000).toISOString(),
    needs_key: false,
    key_configured: false,
    note: 'Run `soc-ai blocklists refresh` to fetch the feeds. Set it in Settings > API keys.',
    ...over,
  };
}

function renderPanel(sources: Row[]) {
  getDataSourcesMock.mockResolvedValue({ sources });
  return render(
    <MemoryRouter>
      <DataSourcesPanel />
    </MemoryRouter>,
  );
}

async function statusOf(name: string): Promise<string> {
  const title = await screen.findByText(name);
  const row = title.closest('div.grid') as HTMLElement;
  return row.lastElementChild?.textContent ?? '';
}

afterEach(() => {
  // Unmount first. The unmount runs the effects React still owes, and those
  // call the mocks. A reset mock returns undefined and breaks the next tests.
  cleanup();
  getDataSourcesMock.mockReset();
});

describe('DataSourcesPanel status', () => {
  it('shows a stale local feed as Stale, never Active', async () => {
    // The row is enabled and present. Only `state` says the feed is stale.
    renderPanel([source({ state: 'stale' })]);
    expect(await statusOf('Blocklists (URLhaus / Feodo / Tor / Spamhaus)')).toBe('Stale');
  });

  it('shows an absent local feed as Missing', async () => {
    renderPanel([
      source({
        id: 'maxmind',
        name: 'MaxMind GeoLite2 (GeoIP / ASN)',
        present: false,
        last_refreshed: null,
        state: 'missing',
      }),
    ]);
    const label = await statusOf('MaxMind GeoLite2 (GeoIP / ASN)');
    expect(label).toBe('Missing');
    expect(screen.queryByText('Not refreshed')).toBeNull();
  });

  it('maps each backend state to its label', async () => {
    renderPanel([
      source({ id: 'a', name: 'Feed A', state: 'active' }),
      source({ id: 'b', name: 'Feed B', state: 'partial' }),
      source({ id: 'c', name: 'Lookup C', category: 'Online lookup', state: 'needs_key' }),
      source({ id: 'd', name: 'Lookup D', category: 'Online lookup', state: 'off' }),
    ]);
    expect(await statusOf('Feed A')).toBe('Active');
    expect(await statusOf('Feed B')).toBe('Partial');
    expect(await statusOf('Lookup C')).toBe('Needs key');
    expect(await statusOf('Lookup D')).toBe('Off');
  });

  // Round 2 (R5-D30): the panel had no row for the grid. The backend now sends
  // it first, with the state of the health probe.
  it('shows the grid row with the probe state and no freshness', async () => {
    renderPanel([
      source({
        id: 'grid',
        name: 'Grid (Security Onion and Elasticsearch)',
        category: 'Grid',
        last_refreshed: null,
        state: 'down',
        note: 'The health probe cannot read Elasticsearch. soc-ai reads alerts and events from the index pattern `logs-*`.',
      }),
      source({ id: 'g2', name: 'Slow grid', category: 'Grid', state: 'slow' }),
      source({ id: 'g3', name: 'Grid not probed', category: 'Grid', state: 'unknown' }),
    ]);
    expect(await statusOf('Grid (Security Onion and Elasticsearch)')).toBe('Down');
    expect(await statusOf('Slow grid')).toBe('Slow');
    expect(await statusOf('Grid not probed')).toBe('Unknown');
    const row = screen.getByText('Grid (Security Onion and Elasticsearch)').closest('div.grid') as HTMLElement;
    expect(row.querySelector('code')?.textContent).toBe('logs-*');
    expect(row.children[2].textContent).toBe('—');
  });

  it('falls back to the old rule when the backend sends no state', async () => {
    renderPanel([source({ id: 'x', name: 'Old row', present: false, state: undefined })]);
    expect(await statusOf('Old row')).toBe('Missing');
  });
});

describe('DataSourcesPanel text', () => {
  it('renders a note with a code span and a section link', async () => {
    renderPanel([source({ state: 'stale' })]);
    const title = await screen.findByText('Blocklists (URLhaus / Feodo / Tor / Spamhaus)');
    const row = title.closest('div.grid') as HTMLElement;
    expect(row.querySelector('code')?.textContent).toBe('soc-ai blocklists refresh');
    expect(row.textContent).not.toContain('`');
    expect(within(row).getByRole('link', { name: 'Settings > API keys' }).getAttribute('href')).toBe(
      '/config#api-keys',
    );
  });

  it('names the grid row in the intro', async () => {
    renderPanel([]);
    expect(
      await screen.findByText(/The first row is the grid\. soc-ai reads every alert and event from it\./),
    ).toBeTruthy();
  });

  it('names the API keys and Online enrichment sections in the intro', async () => {
    renderPanel([]);
    expect(await screen.findByRole('link', { name: 'Settings > API keys' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Settings > Online enrichment' }).getAttribute('href')).toBe(
      '/config#online-enrichment',
    );
    expect(screen.queryByText(/below/)).toBeNull();
  });
});
