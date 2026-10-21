// Dogfood 2026-10-19, R2-D9: the NTLMv1 report and the WMIExec report covered
// one attack step and neither named the other. The report now carries a
// same-flow block beside the alert details, on the page and in the drawer.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getInvestigationSiblings: vi.fn(),
}));

import { getInvestigationSiblings } from '../lib/api';
import { Investigation } from './Investigation';

const NTLM = 'ET INFO NTLMv1 Session Setup Response - Challenge';

const baseInv = (over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-WMI',
    groupId: 'ev-1',
    name: 'ET INFO Suspected Impacket WMIExec Activity',
    kind: 'suricata',
    host: '192.0.2.40',
    ip: '192.0.2.20',
    verdict: 'true_positive',
    conf: 0.72,
    rationale: 'Remote execution over WMI.',
    summary: [{ t: 'text', v: 'evidence' }],
    status: 'complete',
    elapsedLabel: '1m',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    alert: {
      id: 'ev-1',
      rule: 'ET INFO Suspected Impacket WMIExec Activity',
      src: '192.0.2.40:49152',
      dst: '192.0.2.20:135',
      proto: 'tcp',
      action: 'allowed',
      time: new Date(Date.now() - 3_600_000).toISOString(),
      count: 2,
    },
    ...over,
  }) as Inv;

beforeEach(() => {
  vi.mocked(getInvestigationSiblings).mockReset();
  vi.mocked(getInvestigationSiblings).mockResolvedValue({
    siblings: [
      { name: NTLM, kind: 'suricata', verdict: 'false_positive', conf: 0.8, invId: 'INV-NTLM', signals: ['hosts'] },
    ],
    siblingCount: 1,
    reason: null,
  });
});

describe('the same-flow block of a report (R2-D9)', () => {
  it.each(['page', 'drawer'] as const)('shows on the %s with the opposite verdict named', async (layout) => {
    render(
      <MemoryRouter>
        <Investigation layout={layout} inv={baseInv()} />
      </MemoryRouter>,
    );
    const panel = await screen.findByTestId('same-flow-panel');
    expect(getInvestigationSiblings).toHaveBeenCalledWith('INV-WMI');
    expect(panel.textContent).toContain(NTLM);
    expect(panel.textContent).toContain('A false positive shares this flow.');
  });

  it('the drawer hands Show to the screen around it', async () => {
    const onShowSibling = vi.fn();
    render(
      <MemoryRouter>
        <Investigation layout="drawer" inv={baseInv()} onShowSibling={onShowSibling} />
      </MemoryRouter>,
    );
    const panel = await screen.findByTestId('same-flow-panel');
    fireEvent.click(within(panel).getByRole('button', { name: `Show ${NTLM} in Alerts` }));
    expect(onShowSibling).toHaveBeenCalledWith(expect.objectContaining({ name: NTLM }));
  });

  it('the page links Show to the Alerts list', async () => {
    render(
      <MemoryRouter>
        <Investigation layout="page" inv={baseInv()} />
      </MemoryRouter>,
    );
    const panel = await screen.findByTestId('same-flow-panel');
    const link = within(panel).getByRole('link', { name: `Show ${NTLM} in Alerts` });
    expect(link.getAttribute('href')).toContain('/alerts?');
  });

  it('NEGATIVE CONTROL: a hunt has no alert, so the page asks for no flow', async () => {
    render(
      <MemoryRouter>
        <Investigation
          layout="page"
          inv={baseInv({
            kind: 'hunt',
            alert: undefined,
            subject: {
              type: 'hunt',
              hunt_id: '01HUNTABC000000000000000000',
              objective: 'Sweep for remote execution',
              finding_ordinals: [0],
              finding_titles: ['WMI execution'],
              lead_id: null,
              document_ids: [],
              observation_ids: [],
            },
          } as Partial<Inv>)}
        />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getAllByText(/Sweep for remote execution/).length).toBeGreaterThan(0));
    expect(getInvestigationSiblings).not.toHaveBeenCalled();
    expect(screen.queryByTestId('same-flow-panel')).toBeNull();
  });
});
