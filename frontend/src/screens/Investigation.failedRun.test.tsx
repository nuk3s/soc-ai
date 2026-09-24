// A triage that died has to be clearable from the run itself.
//
// Production carried 188 runs in this state (status 'error', no verdict, no
// rationale, no report) over ten weeks. None was ever acknowledged, because
// there was nothing to acknowledge with: the Dismiss control lived only in the
// E1.2 fallback panel, which needs a report to mark, and these wrote none. A
// count that can never be worked down is a count the owner learns to ignore.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

const dismissInvestigationError = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  dismissInvestigationError,
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
}));

import { Investigation } from './Investigation';

const baseInv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-DEAD',
    groupId: 'ev-dead',
    name: 'ET USER_AGENTS Steam HTTP Client User-Agent',
    kind: 'suricata',
    host: '192.0.2.10',
    ip: '198.51.100.7',
    verdict: 'untriaged',
    conf: 0,
    rationale: '',
    summary: [{ t: 'text', v: '' }],
    status: 'error',
    elapsedLabel: '10m 0s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

const mount = (over: Partial<Inv> = {}) =>
  render(
    <MemoryRouter>
      <Investigation inv={baseInv(over)} layout="page" />
    </MemoryRouter>,
  );

beforeEach(() => {
  dismissInvestigationError.mockReset();
  dismissInvestigationError.mockResolvedValue({ ok: true });
});

describe('a run that died without a verdict', () => {
  it('offers Dismiss beside Re-run', async () => {
    mount();
    fireEvent.click(screen.getByRole('button', { name: /^Dismiss/ }));
    await waitFor(() => expect(dismissInvestigationError).toHaveBeenCalledWith('INV-DEAD'));
    expect(await screen.findByText(/The Dashboard does not count this run/i)).toBeTruthy();
  });

  it('reports an already-dismissed run as done, with no button to press again', () => {
    mount({ errorDismissed: true });
    expect(screen.getByText(/The Dashboard does not count this run/i)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /^Dismiss/ })).toBeNull();
  });

  // Negative control: the two benign terminal states carry no failure to clear.
  // A cancel was asked for and a restart orphan is re-huntable by design, so
  // offering an ack on either would invite the owner to file away a run that
  // never needed filing.
  it('offers no Dismiss on a cancelled or interrupted run', () => {
    const { unmount } = mount({ status: 'cancelled' });
    expect(screen.queryByRole('button', { name: /^Dismiss/ })).toBeNull();
    unmount();

    mount({ status: 'interrupted' });
    expect(screen.queryByRole('button', { name: /^Dismiss/ })).toBeNull();
  });

  it('offers no Dismiss on a run that reached a verdict', () => {
    mount({ status: 'complete', verdict: 'false_positive', conf: 0.9 });
    expect(screen.queryByRole('button', { name: /^Dismiss/ })).toBeNull();
  });
});
