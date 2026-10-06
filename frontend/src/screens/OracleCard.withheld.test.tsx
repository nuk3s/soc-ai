// No override without evidence (2026-10-04). An Oracle answer that changed the
// class with no evidence that resolves is an opinion on the run. The card and
// the badge must never say "overrode" for it: the local verdict stands.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv, OracleAdjudication } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations: vi.fn().mockResolvedValue({
    rows: [],
    total: 0,
    running: 0,
    truePositives: 0,
    totalAll: 0,
    active: false,
    limit: 50,
    offset: 0,
  }),
}));

import { Investigation } from './Investigation';

const inv = (oracle: OracleAdjudication): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET INFO Packed Executable Download',
    kind: 'suricata',
    host: '192.0.2.10',
    ip: '198.51.100.7',
    verdict: 'needs_more_info',
    conf: 0.4,
    rationale: 'Unsure.',
    summary: [{ t: 'text', v: 'unsure' }],
    status: 'complete',
    elapsedLabel: '8s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    oracle,
  }) as Inv;

describe('Oracle card, withheld opinion', () => {
  it('says opinion only and never overrode', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={inv({
            escalated: true,
            reason: 'needs_more_info',
            localVerdict: 'needs_more_info',
            oracleVerdict: 'false_positive',
            oracleConfidence: 0.93,
            changed: true,
            withheld: true,
          })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.getAllByText('opinion only').length).toBeGreaterThan(0);
    expect(screen.getByTestId('oracle-opinion-note')).toHaveTextContent(
      'The Oracle cited no evidence that resolves.',
    );
    expect(screen.queryByText('overrode')).toBeNull();
    expect(screen.queryByText(/Oracle overrode/)).toBeNull();
  });

  it('still says overrode for a flip that cited evidence', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={inv({
            escalated: true,
            reason: 'needs_more_info',
            localVerdict: 'needs_more_info',
            oracleVerdict: 'false_positive',
            oracleConfidence: 0.93,
            changed: true,
            withheld: false,
          })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.getAllByText('overrode').length).toBeGreaterThan(0);
    expect(screen.queryByTestId('oracle-opinion-note')).toBeNull();
  });
});
