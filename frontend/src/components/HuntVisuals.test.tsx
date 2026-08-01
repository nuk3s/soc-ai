// Pins the charts' non-hover path (DESIGN Q6): every chart panel exposes a
// 'View as table' <details> that re-renders the exact same series as a real
// semantic <table>. That table is the screen-reader / touch / no-pointer
// fallback for the hover tooltips, so its cell contents are the contract we
// guard here — not the recharts SVG (which never sizes under a headless DOM).
//
// happy-dom has no ResizeObserver; recharts' ResponsiveContainer needs one, so
// we install a no-op polyfill before rendering. The tables live OUTSIDE the
// ResponsiveContainer, so they render synchronously regardless of chart size.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeAll, describe, expect, it } from 'vitest';
import type { HuntChart, HuntFinding } from '../lib/types';
import { HuntVisuals } from './HuntVisuals';

beforeAll(() => {
  // recharts ResponsiveContainer observes size via ResizeObserver.
  (globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
});

function finding(o: Partial<HuntFinding> = {}): HuntFinding {
  return { title: 'f', detail: '', severity: 'info', hosts: [], citations: [], ...o };
}

const FINDINGS: HuntFinding[] = [
  finding({ title: 'Beacon to C2', severity: 'high', category: 'threat', hosts: ['host-a', 'host-b'] }),
  finding({ title: 'No EDR coverage', severity: 'medium', category: 'visibility_gap', hosts: ['host-a'] }),
  finding({ title: 'DNS lookups', severity: 'low', category: 'observation', hosts: [] }),
];

function renderVisuals(charts: HuntChart[] = []) {
  return render(
    <MemoryRouter>
      <HuntVisuals findings={FINDINGS} charts={charts} />
    </MemoryRouter>,
  );
}

describe('HuntVisuals — View as table (non-hover path)', () => {
  it('renders a table disclosure for each deterministic panel', () => {
    renderVisuals();
    // breakdown + host involvement + host–finding map
    expect(screen.getAllByText('View as table')).toHaveLength(3);
    // each disclosure holds a real semantic <table>
    expect(screen.getAllByRole('table').length).toBeGreaterThanOrEqual(3);
  });

  it('breakdown table carries the severity rows and the stack total', () => {
    renderVisuals();
    const table = screen
      .getByText('Findings breakdown by severity and category')
      .closest('table') as HTMLElement;
    // header includes the Total column the chart can only show on hover
    expect(within(table).getByText('Total')).toBeInTheDocument();
    // high row present (1 threat, total 1)
    const highRow = within(table).getByText('high').closest('tr') as HTMLElement;
    expect(highRow).toHaveTextContent('high');
    // medium is a visibility gap; low is an observation — both present as rows
    expect(within(table).getByText('medium')).toBeInTheDocument();
    expect(within(table).getByText('low')).toBeInTheDocument();
  });

  it('host table lists involvement counts and worst severity per host', () => {
    renderVisuals();
    const table = screen
      .getByText('Host involvement — findings per host')
      .closest('table') as HTMLElement;
    const rowA = within(table).getByText('host-a').closest('tr') as HTMLElement;
    // host-a is named by the high threat and the medium gap → 2 findings, worst high
    expect(within(rowA).getByText('2')).toBeInTheDocument();
    expect(within(rowA).getByText('high')).toBeInTheDocument();
    expect(within(table).getByText('host-b')).toBeInTheDocument();
  });

  it('host–finding map table names each finding and its hosts', () => {
    renderVisuals();
    const table = screen
      .getByText('Host–finding map — each finding and the hosts it names')
      .closest('table') as HTMLElement;
    expect(within(table).getByText('F1 — Beacon to C2')).toBeInTheDocument();
    // a finding that names no host renders an em dash, not an empty cell
    const noHostRow = within(table).getByText('F3 — DNS lookups').closest('tr') as HTMLElement;
    expect(within(noHostRow).getByText('—')).toBeInTheDocument();
  });

  it('agent charts add their own x/y data table with labelled columns', () => {
    renderVisuals([
      {
        kind: 'bar',
        title: 'Beacon interval',
        xLabel: 'seconds since prior',
        yLabel: 'events',
        series: [
          { x: '30', y: 5 },
          { x: '60', y: 9 },
        ],
      },
    ]);
    // 3 deterministic + 1 agent chart
    expect(screen.getAllByText('View as table')).toHaveLength(4);
    const table = screen.getByText('Beacon interval — data table').closest('table') as HTMLElement;
    expect(within(table).getByText('seconds since prior')).toBeInTheDocument();
    expect(within(table).getByText('events')).toBeInTheDocument();
    expect(within(table).getByText('30')).toBeInTheDocument();
    expect(within(table).getByText('60')).toBeInTheDocument();
    expect(within(table).getByText('5')).toBeInTheDocument();
    expect(within(table).getByText('9')).toBeInTheDocument();
  });

  it('host involvement header hints "top 8 of N" when more than 8 hosts are named', () => {
    const many: HuntFinding[] = Array.from({ length: 10 }, (_, i) =>
      finding({ title: `f${i}`, severity: 'medium', category: 'threat', hosts: [`host-${i}`] }),
    );
    render(
      <MemoryRouter>
        <HuntVisuals findings={many} />
      </MemoryRouter>,
    );
    expect(screen.getByText('top 8 of 10')).toBeInTheDocument();
  });

  it('host involvement panel carries a legend explaining bar color = worst severity', () => {
    renderVisuals();
    expect(screen.getByText('bar color = worst severity')).toBeInTheDocument();
  });
});
