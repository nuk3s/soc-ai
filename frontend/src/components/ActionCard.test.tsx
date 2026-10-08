// The recommended action card (dogfood 2026-10-06). An ack states its scope
// before the click, every write and every dismissal asks for a confirm, a
// dismissal shows who and when with an undo. The negative controls: the
// first click never writes, and Cancel writes nothing.
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { RecommendedAction } from '../lib/types';

const getActionScope = vi.fn();
vi.mock('../lib/api', () => ({
  getActionScope: (...a: unknown[]) => getActionScope(...a),
}));

import { ActionCard, clockTime, confirmLabel } from './ActionCard';

const ack: RecommendedAction = { id: 'a0', title: 'Acknowledge alert', tag: 'ack', rationale: 'Benign.' };
const esc: RecommendedAction = { id: 'a1', title: 'Escalate to case', tag: 'escalate', rationale: 'Bad.' };

const GROUP_SCOPE = {
  tool: 'ack_alert',
  scope: 'group',
  count: 9,
  hosts: 2,
  held: 0,
  rangeLabel: 'the last 7 days',
  sentence: 'Acknowledge 9 alerts of this rule from the last 7 days, on 2 hosts.',
};

function mount(action: RecommendedAction, over: Partial<Parameters<typeof ActionCard>[0]> = {}) {
  const props = {
    action,
    index: 0,
    invId: 'INV-1',
    onExecute: vi.fn(),
    onDismiss: vi.fn(),
    onUndoDismiss: vi.fn(),
    ...over,
  };
  render(<ActionCard {...props} />);
  return props;
}

describe('ActionCard', () => {
  it('states the ack scope before the click and confirms before it writes', async () => {
    getActionScope.mockResolvedValueOnce(GROUP_SCOPE);
    const p = mount(ack);
    await waitFor(() =>
      expect(screen.getByTestId('action-scope').textContent).toBe(GROUP_SCOPE.sentence),
    );
    fireEvent.click(screen.getByRole('button', { name: /^Acknowledge$/ }));
    // Negative control: the first click opens the confirm and writes nothing.
    expect(p.onExecute).not.toHaveBeenCalled();
    const confirm = screen.getByTestId('action-confirm');
    expect(confirm.textContent).toContain('This writes to Security Onion.');
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge 9 alerts' }));
    expect(p.onExecute).toHaveBeenCalledWith('group');
  });

  it('offers "Acknowledge this alert only" on a group ack', async () => {
    getActionScope.mockResolvedValueOnce(GROUP_SCOPE);
    const p = mount(ack);
    await waitFor(() => screen.getByText(GROUP_SCOPE.sentence));
    fireEvent.click(screen.getByRole('button', { name: /^Acknowledge$/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge this alert only' }));
    expect(p.onExecute).toHaveBeenCalledWith('alert');
  });

  it('says what an escalate does and writes nothing on Cancel', () => {
    getActionScope.mockClear();
    const p = mount(esc);
    expect(screen.getByTestId('action-scope').textContent).toBe(
      'Open one Security Onion case for this alert.',
    );
    fireEvent.click(screen.getByRole('button', { name: /Escalate to case/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(p.onExecute).not.toHaveBeenCalled();
    expect(screen.queryByTestId('action-confirm')).toBeNull();
    // An escalate needs no count from the server.
    expect(getActionScope).not.toHaveBeenCalled();
  });

  it('confirms a dismissal before it stores it', () => {
    const p = mount(esc);
    fireEvent.click(screen.getByRole('button', { name: /Dismiss/ }));
    expect(p.onDismiss).not.toHaveBeenCalled();
    expect(screen.getByTestId('dismiss-confirm').textContent).toContain('You can undo it.');
    fireEvent.click(screen.getByRole('button', { name: /Confirm dismiss/ }));
    expect(p.onDismiss).toHaveBeenCalledTimes(1);
  });

  it('shows who dismissed and when, with an undo', () => {
    const at = '2026-10-06T11:09:00+00:00';
    const p = mount(esc, { dismissal: { by: 'alice', at } });
    expect(screen.getByTestId('action-dismissed').textContent).toContain(
      `Dismissed by alice at ${clockTime(at)}.`,
    );
    fireEvent.click(screen.getByRole('button', { name: /Undo/ }));
    expect(p.onUndoDismiss).toHaveBeenCalledTimes(1);
    // A dismissed card offers no write.
    expect(screen.queryByRole('button', { name: /Escalate to case/ })).toBeNull();
  });

  it('turns every button off when a newer run replaced the run', () => {
    mount(esc, { lockedReason: 'A newer run replaced this run.' });
    expect(screen.getByRole('button', { name: /Escalate to case/ })).toBeDisabled();
    expect(screen.getByRole('button', { name: /Dismiss/ })).toBeDisabled();
  });

  it('falls back to a plain sentence when the count does not arrive', async () => {
    getActionScope.mockRejectedValueOnce(new Error('down'));
    await act(async () => {
      mount(ack);
    });
    await waitFor(() =>
      expect(screen.getByTestId('action-scope').textContent).toContain(
        'soc-ai could not count the alerts.',
      ),
    );
  });

  it('labels the confirm with the count', () => {
    expect(confirmLabel('ack', { ...GROUP_SCOPE, scope: 'group', count: 1 })).toBe('Acknowledge 1 alert');
    expect(confirmLabel('ack', null)).toBe('Acknowledge this alert');
    expect(confirmLabel('escalate', null)).toBe('Open the case');
  });
});
