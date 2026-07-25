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
]);

const startQualityEvalMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue([]),
  getInvestigations: vi.fn().mockResolvedValue(ROWS),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
  startQualityEval: startQualityEvalMock,
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
