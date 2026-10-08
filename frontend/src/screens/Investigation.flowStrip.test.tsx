// The flow strip under the header of the alert drawer and the investigation
// page (owner, 2026-10-07: "What is the user flow?"). The strip reads the
// run's own state: Alert, Investigation, Verdict, Action in Security Onion.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({ sigma_authoring_enabled: false }),
  ackGroup: vi.fn().mockResolvedValue({ acked: 1, total: 1 }),
  escalateGroup: vi.fn(),
}));

import { Investigation } from './Investigation';

const baseInv = (over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET POLICY curl user agent',
    kind: 'suricata',
    host: '192.0.2.10',
    ip: '198.51.100.7',
    verdict: 'false_positive',
    conf: 0.9,
    rationale: 'A package mirror fetch.',
    summary: [{ t: 'text', v: 'A package mirror fetch.' }],
    status: 'complete',
    elapsedLabel: '1m 5s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

const mount = (inv: Inv, layout: 'page' | 'drawer') =>
  render(
    <MemoryRouter>
      <Investigation inv={inv} layout={layout} />
    </MemoryRouter>,
  );

describe.each(['drawer', 'page'] as const)('the flow strip in the %s', (layout) => {
  it('sits first, under the header, with the investigation as the current step', () => {
    const { container } = mount(baseInv(), layout);
    const strip = screen.getByTestId('flow-strip');
    // The first block of the body: nothing sits between the header and it.
    expect(container.querySelector('[data-testid="flow-strip"]')).toBe(strip);
    expect(strip.parentElement?.firstElementChild).toBe(strip);
    expect(
      within(strip)
        .getAllByRole('listitem')
        .map((li) => li.dataset.state),
    ).toEqual(['done', 'current', 'done', 'next']);
    expect(within(strip).getByTestId('flow-step-investigation').getAttribute('aria-current')).toBe(
      'step',
    );
    expect(strip.textContent).toContain('Action in Security Onion');
    expect(within(strip).getByTestId('flow-control-action').textContent).toBe(
      '· Acknowledge or Escalate to case',
    );
  });

  // Negative control: a failed run has no verdict. The strip names Re-run and
  // never reads the verdict as done.
  it('names Re-run on a failed run, and no verdict', () => {
    mount(baseInv({ status: 'error', verdict: 'untriaged' }), layout);
    const strip = screen.getByTestId('flow-strip');
    expect(within(strip).getByTestId('flow-step-verdict').dataset.state).toBe('next');
    expect(within(strip).getByTestId('flow-control-verdict').textContent).toBe(
      '· Re-run investigation',
    );
    expect(within(strip).getByTestId('flow-step-action').dataset.state).toBe('not_yet');
  });
});

describe('the flow strip after an action', () => {
  it('reads Action done once the settled bar acknowledges the alert', async () => {
    mount(baseInv(), 'drawer');
    const strip = screen.getByTestId('flow-strip');
    expect(within(strip).getByTestId('flow-step-action').dataset.state).toBe('next');
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge' }));
    fireEvent.click(screen.getByRole('button', { name: /Confirm acknowledge/ }));
    await waitFor(() =>
      expect(within(strip).getByTestId('flow-step-action').dataset.state).toBe('done'),
    );
  });

  it('reads Action done on a run whose action an earlier hand executed', () => {
    mount(
      baseInv({
        actions: [
          { id: 'a1', title: 'Acknowledge the alert', tag: 'ack', rationale: 'r', applied: true },
        ],
      }),
      'page',
    );
    const strip = screen.getByTestId('flow-strip');
    expect(within(strip).getByTestId('flow-step-action').dataset.state).toBe('done');
    expect(strip.querySelector('[data-state="next"]')).toBeNull();
  });
});
