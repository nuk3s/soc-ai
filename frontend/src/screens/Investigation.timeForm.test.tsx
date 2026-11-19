// One time form on the investigation page (dogfood 2026-11-17, AA5). One
// event showed in local time, in UTC and as a raw ISO string on one page. The
// page now states each time in UTC, the form of its Event timeline.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
}));

import { Investigation } from './Investigation';

const AT = '2026-11-04T15:36:54.000Z';
const SHOWN = '2026-11-04 15:36:54 UTC';

const inv = (): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET SCAN NMAP -sS window 1024',
    kind: 'suricata',
    host: '198.51.100.74',
    ip: '192.0.2.2',
    srcIp: '198.51.100.74',
    dstIp: '192.0.2.2',
    verdict: 'true_positive',
    conf: 0.75,
    rationale: 'The external source probed a workstation at 2026-11-04T15:36:54Z.',
    summary: [{ t: 'text', v: 'At 2026-11-04T15:36:54Z the external host sent one TCP SYN.' }],
    status: 'complete',
    elapsedLabel: '1m 40s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    alert: { rule: 'ET SCAN NMAP -sS window 1024', src: '198.51.100.74', dst: '192.0.2.2', proto: 'tcp', action: 'allowed', count: 1, time: AT },
    meta: { model: 'm', ranBy: 'scheduler', ranAt: AT, eventAt: AT, toolCalls: 3, pivots: 1 },
  }) as Inv;

describe('the time form of the investigation page', () => {
  it('states the event in UTC in the text, the alert details and the record', () => {
    const { container } = render(
      <MemoryRouter>
        <Investigation inv={inv()} layout="page" />
      </MemoryRouter>,
    );
    expect(screen.getByTestId('verdict-headline').textContent).toContain(SHOWN);
    expect(container.textContent).toContain(`At ${SHOWN} the external host`);
    // No raw ISO string and no local time with another zone.
    expect(container.textContent).not.toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/);
    expect(container.textContent).not.toMatch(/\b(?:AM|PM)\b/);
    const alertTime = screen.getByText('alert time').parentElement as HTMLElement;
    expect(alertTime.textContent).toBe(`alert time${SHOWN}`);
  });
});
