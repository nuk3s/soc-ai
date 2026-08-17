// The auto-triage completion toast spells out WHY work was skipped, from the
// backend's per-reason tally. Two things are pinned here:
//
//   1. "no_ip" is RETIRED. The planner used to DROP every alert with no
//      source/destination IP under that reason, which made the scheduled sweep
//      network-flow-only — endpoint/process-shaped detections (Sigma host rules
//      carry no source.*/destination.*) were seen and discarded on every sweep,
//      forever. autotriage.py::_cluster_events now degrades the cluster key
//      instead of dropping, so nothing can emit the code. The label describing
//      that behaviour must be gone with it.
//   2. Historical status rows can still hold a retired (or a not-yet-known)
//      code, so the fallback has to stay legible: humanized words, never a raw
//      snake_case token leaking the wire format into the toast.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '../lib/toast';
import { ShellProvider } from '../shell/ShellContext';

const GROUP = vi.hoisted(() => ({
  id: 'g1',
  name: 'ET SCAN Test Detection',
  kind: 'suricata',
  sev: 'high',
  count: 3,
  verdict: 'untriaged',
  conf: null,
  latest: '2m ago',
  inherited: false,
  events: [],
}));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue([GROUP]),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
  startAutoTriage: vi.fn(),
  getAutoTriageStatus: vi.fn(),
}));

import { type AutoTriageStatus, startAutoTriage } from '../lib/api';
import { Alerts } from './Alerts';

/** A batch that has already wrapped up, so the click resolves straight to the
 *  completion toast without needing the 2 s status poll. */
const finished = (reasons: Record<string, number>): AutoTriageStatus => ({
  active: false,
  total: 5,
  hunted: 2,
  skipped: Object.values(reasons).reduce((a, b) => a + b, 0),
  failed: 0,
  finished_at: null,
  severities: ['critical', 'high'],
  note: null,
  current: null,
  tool_calls: 0,
  skipped_reasons: reasons,
});

/** Click the header's global sweep button and wait for its completion toast. */
async function sweep(): Promise<void> {
  render(
    <ToastProvider>
      <MemoryRouter initialEntries={['/alerts']}>
        <ShellProvider>
          <Alerts />
        </ShellProvider>
      </MemoryRouter>
    </ToastProvider>,
  );
  await screen.findByText(GROUP.name);
  fireEvent.click(screen.getByRole('button', { name: /Bulk Investigate/ }));
}

describe('auto-triage skip-reason labels', () => {
  beforeEach(() => {
    vi.mocked(startAutoTriage).mockReset();
  });

  it('no longer claims a skip was for want of a source/dest IP', async () => {
    vi.mocked(startAutoTriage).mockResolvedValue(finished({ already_triaged: 2, no_ip: 1 }));
    await sweep();

    await screen.findByText('2 investigated · 3 skipped (2 already triaged, 1 no ip)');
    expect(screen.queryByText(/no source\/dest IP/)).toBeNull();
  });

  it('humanizes an unrecognized reason code instead of leaking the raw code', async () => {
    vi.mocked(startAutoTriage).mockResolvedValue(finished({ some_new_reason: 3 }));
    await sweep();

    await screen.findByText('2 investigated · 3 skipped (3 some new reason)');
  });

  // "not_found" carried a hand-written label whose text the humanizing fallback
  // now reproduces exactly, so the entry was dropped as redundant. This pins the
  // rendering that made the removal free.
  it('reads "not found" for a code with no hand-written label', async () => {
    vi.mocked(startAutoTriage).mockResolvedValue(finished({ not_found: 3 }));
    await sweep();

    await screen.findByText('2 investigated · 3 skipped (3 not found)');
  });

  it('still spells out the reasons the planner does emit', async () => {
    vi.mocked(startAutoTriage).mockResolvedValue(
      finished({ already_triaged: 2, running: 1, inherited: 1 }),
    );
    await sweep();

    await screen.findByText(
      '2 investigated · 4 skipped (2 already triaged, 1 in-flight, 1 covered by a prior verdict)',
    );
  });
});
