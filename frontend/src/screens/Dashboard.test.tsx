// A pipeline-error run (E1.2 fallback) in the Dashboard's "Recent investigations"
// list must show the red PipelineErrorChip — the same treatment the Investigations
// and Alerts lists give it — not the amber Needs-info pill its placeholder verdict
// would otherwise earn. The chip means "infra broke, retry"; the pill would read
// as "the analyst should dig deeper", which is exactly the wrong signal.
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { DemoProvider } from '../lib/demo';

const ROWS = vi.hoisted(() => [
  {
    id: 'INV-FB',
    name: 'ET Fallback Run',
    kind: 'suricata',
    verdict: 'needs_more_info',
    conf: 0.3,
    host: '192.0.2.10',
    dst: '198.51.100.7',
    status: 'complete',
    when: '1m ago',
    ts: '2026-07-14T10:00:00+00:00',
    fallback: true,
  },
  {
    id: 'INV-NMI',
    name: 'ET Genuine NMI',
    kind: 'suricata',
    verdict: 'needs_more_info',
    conf: 0.55,
    host: '192.0.2.11',
    dst: '198.51.100.8',
    status: 'complete',
    when: '2m ago',
    ts: '2026-07-14T09:59:00+00:00',
    fallback: false,
  },
  {
    // A real-length Suricata rule name — the case the narrow-width row has to
    // survive (see the row-layout describe at the bottom of this file).
    id: 'INV-LONG',
    name: 'ET MALWARE Win32/Emotet CnC Activity Observed (Variant B) M2',
    kind: 'suricata',
    verdict: 'true_positive',
    conf: 0.88,
    host: '192.0.2.70',
    dst: '10.0.0.40',
    status: 'complete',
    when: '3m ago',
    ts: '2026-07-14T09:58:00+00:00',
    fallback: false,
  },
]);

const LONG_NAME = 'ET MALWARE Win32/Emotet CnC Activity Observed (Variant B) M2';

const startQualityEvalMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue([]),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  // The recent-sample call feeds ROWS; the pipeline-error KPI's own query
  // (verdict filter set) answers empty — these tests exercise the recent list.
  listInvestigations: vi.fn().mockImplementation(async (q: { verdict?: string[] } = {}) => ({
    rows: q.verdict?.length ? [] : ROWS,
    total: q.verdict?.length ? 0 : ROWS.length,
    running: 0,
    truePositives: 0,
    totalAll: ROWS.length,
    active: false,
    limit: 100,
    offset: 0,
  })),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
  startQualityEval: startQualityEvalMock,
  // Setup-health card: unconditional on mount, so every Dashboard-rendering
  // test needs it named or the global fetch guard rejects loudly. Green here
  // (this file isn't about setup health), so the admin-only detail read is
  // never reached regardless of role.
  getMe: vi.fn().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' }),
  getPreflight: vi.fn().mockResolvedValue({ status: 'green', failing: 0, warned: 0, checked_at: '2026-08-19T00:00:00+00:00' }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-08-19T00:00:00+00:00' }),
}));

import { Dashboard } from './Dashboard';

describe('Dashboard recent investigations', () => {
  it('renders a pipeline-error run with the chip, not the Needs-info pill', async () => {
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );
    const fbRow = (await screen.findByText('ET Fallback Run')).closest('button')!;
    expect(within(fbRow).getByText('Pipeline error')).toBeTruthy();
    expect(within(fbRow).queryByText('Needs info')).toBeNull();
  });

  it('keeps the Needs-info pill on a genuine needs_more_info run', async () => {
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );
    const nmiRow = (await screen.findByText('ET Genuine NMI')).closest('button')!;
    expect(within(nmiRow).getByText('Needs info')).toBeTruthy();
    expect(within(nmiRow).queryByText('Pipeline error')).toBeNull();
  });
});

// The "Run now" quality-eval button was a new 1.2.x write with zero demo
// wiring — a click fired a doomed POST /quality/eval/run in the read-only
// demo instead of showing the standard note. Drives the real Dashboard
// through DemoProvider so it exercises the actual runEvalNow handler.
describe('Dashboard quality eval — demo guard', () => {
  it('shows the demo note and does not POST /quality/eval/run', async () => {
    render(
      <MemoryRouter>
        <DemoProvider demo>
          <Dashboard />
        </DemoProvider>
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByText('Run now'));
    await screen.findByText(/Not available in the read-only demo/);
    expect(startQualityEvalMock).not.toHaveBeenCalled();
  });
});

// Below `lg` the row used to render as "SURICATA │ E… │ 192.0.2.70 → 10.0.0.40"
// (dogfood, 2026-08-12): the flow's 230px floor and the fixed status column ate
// the line, and the one element with no floor — the detection name — collapsed
// to a single character. A row that names no detection is a row an analyst
// cannot read, and this is the landing screen's only list.
describe('Dashboard recent-investigations row layout', () => {
  const row = async () => {
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );
    return (await screen.findByTitle(LONG_NAME)) as HTMLElement;
  };

  it('renders the whole detection name — nothing is clipped in JS', async () => {
    const name = await row();
    // Guards the cheap "fix": shortening the string instead of the layout.
    // Clipping stays CSS-only, so the full name is in the DOM (and the title
    // attribute), and the tooltip an analyst hovers is the real rule name.
    expect(name.textContent).toBe(LONG_NAME);
    expect(name.textContent!.length).toBeGreaterThan(40);
  });

  it('stacks the name above the endpoints below lg, so the flow yields width, not the name', async () => {
    const name = await row();
    // jsdom has no layout engine, so the pixel proof of "legible at 900px" is
    // the render gate. What is checkable here is the contract that produced the
    // clipped row: the name and the flow sharing one line while only the flow
    // had a width floor. Now they share a SLOT that is a column below `lg`…
    const slot = name.parentElement!;
    expect(slot.className).toContain('flex-col');
    expect(slot.className).toContain('lg:flex-row');
    // …and the 230px two-IPv4 floor only applies where there is room for it.
    const flow = name.nextElementSibling as HTMLElement;
    expect(flow.className).toContain('lg:min-w-[230px]');
    expect(flow.className).not.toMatch(/(^|\s)min-w-\[230px\]/);
    // The endpoints are not dropped to buy the width at tablet/laptop sizes —
    // they move to the second line and both facts stay on the row.
    expect(within(flow).getByTitle('192.0.2.70 → 10.0.0.40')).toBeTruthy();
  });
});
