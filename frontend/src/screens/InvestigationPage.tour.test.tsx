// The Investigation tour names anchors on the permalink page and in the report
// it composes. This smoke test renders a complete alert run with citations,
// a recommended action, a timeline and host context, so every anchor of the
// tour is on the page.
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';
import { INVESTIGATION_TOUR } from '../tours/content';
import { missingAnchors } from '../tours/testing';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getInvestigation: vi.fn(),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
}));

import { getInvestigation } from '../lib/api';
import { InvestigationPage } from './InvestigationPage';

const sig = (label: string) => ({ time: '', label, tone: 'low' as const, w: 50, sev: '2×' });

const run = {
  id: 'INV-1',
  groupId: 'ev-1',
  name: 'ET MALWARE Known C2 Beacon',
  kind: 'suricata',
  host: '192.0.2.10',
  ip: '198.51.100.7',
  verdict: 'true_positive',
  conf: 0.84,
  rationale: 'The host beacons to a known C2 address every 60 seconds.',
  summary: [
    { t: 'text', v: 'The flow repeats every 60 seconds.' },
    { t: 'cite', n: 1 },
  ],
  citations: [{ kind: 'id', target: 'doc-1', text: 'doc-1', resolved: true }],
  status: 'complete',
  elapsedLabel: '4m 5s',
  actions: [
    {
      id: 'a0',
      title: 'Escalate to case',
      tag: 'escalate',
      rationale: 'The beacon matches a known C2 address.',
    },
  ],
  timeline: [
    {
      id: 's1',
      group: 'Prefetch & pivots',
      title: 'Context gathered for 192.0.2.10',
      detail: 'Two flows to 198.51.100.7.',
      time: '00:01',
    },
  ],
  nodes: [],
  edges: [],
  seedChat: [],
  alert: {
    id: 'ev-1',
    rule: 'ET MALWARE Known C2 Beacon',
    src: '192.0.2.10:49152',
    dst: '198.51.100.7:443',
    proto: 'tcp',
    action: 'allowed',
    count: 3,
    time: new Date(Date.now() - 3_600_000).toISOString(),
  },
  hostContexts: [
    { ip: '192.0.2.10', end: 'source', asSource: [sig('ET POLICY fetch')], asDestination: [] },
  ],
} as unknown as Inv;

describe('the Investigation tour', () => {
  it('finds every anchor on the page of a complete alert run', async () => {
    vi.mocked(getInvestigation).mockResolvedValue(run);
    render(
      <MemoryRouter initialEntries={['/investigation/INV-1']}>
        <Routes>
          <Route path="/investigation/:id" element={<InvestigationPage />} />
        </Routes>
      </MemoryRouter>,
    );
    await screen.findByTestId('cited-evidence');
    expect(missingAnchors(INVESTIGATION_TOUR)).toEqual([]);
  });

  it('puts the actions anchor on the settled bar of a run with no recommended action', async () => {
    vi.mocked(getInvestigation).mockResolvedValue({ ...run, actions: [] } as Inv);
    render(
      <MemoryRouter initialEntries={['/investigation/INV-1']}>
        <Routes>
          <Route path="/investigation/:id" element={<InvestigationPage />} />
        </Routes>
      </MemoryRouter>,
    );
    await screen.findByText('No automatic action');
    expect(missingAnchors(INVESTIGATION_TOUR)).toEqual([]);
  });
});
