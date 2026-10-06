// The endpoints chip reads the alert's own fields (range dogfood 2026-10-05).
//
// A host-reported alert names a source address and a host, and no
// destination. The chip put the host name in the source slot and the source
// address in the destination slot, so a grid node login failure read
// "source <node> to destination <attacker>". The host that reported the alert
// is named "on <host>" and never sits in a direction slot.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
}));

import { Investigation, alertEnds } from './Investigation';

const baseInv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'Grid Node Login Failure (SSH)',
    kind: 'sigma',
    host: '192.0.2.226',
    ip: '—',
    verdict: 'false_positive',
    conf: 0.68,
    rationale: 'A failed login from a known address.',
    summary: [{ t: 'text', v: 'evidence' }],
    status: 'complete',
    elapsedLabel: '1m 5s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

const mount = (over: Partial<Inv>) =>
  render(
    <MemoryRouter>
      <Investigation inv={baseInv(over)} layout="page" />
    </MemoryRouter>,
  );

describe('the endpoints chip', () => {
  it('keeps the source of a host-reported alert and names the host apart', () => {
    mount({ srcIp: '192.0.2.226', dstIp: null, reportedBy: 'gridnode' });
    const chip = screen.getByTestId('verdict-endpoints');
    expect(within(chip).getByTestId('endpoint-src').textContent).toBe('192.0.2.226');
    expect(within(chip).queryByTestId('endpoint-dst')).toBeNull();
    expect(within(chip).getByTestId('endpoint-on').textContent).toBe('gridnode');
    expect(chip.textContent).toBe('from 192.0.2.226 on gridnode');
    expect(chip.getAttribute('title')).toBe(
      'Source 192.0.2.226. The alert names no destination. The host gridnode reported the alert.',
    );
    // The host name is in no direction slot, and the source is not the destination.
    expect(chip.textContent).not.toContain('→');
    expect(chip.getAttribute('title')).not.toContain('destination 192.0.2.226');
  });

  it('keeps both ends of a flow alert in their slots', () => {
    mount({ srcIp: '192.0.2.10', dstIp: '198.51.100.7', reportedBy: 'sensor-a' });
    const chip = screen.getByTestId('verdict-endpoints');
    expect(within(chip).getByTestId('endpoint-src').textContent).toBe('192.0.2.10');
    expect(within(chip).getByTestId('endpoint-dst').textContent).toBe('198.51.100.7');
    expect(within(chip).getByTestId('endpoint-on').textContent).toBe('sensor-a');
    expect(chip.textContent).toBe('192.0.2.10 → 198.51.100.7 on sensor-a');
  });

  it('names no reporter when the alert names none', () => {
    mount({ srcIp: '192.0.2.10', dstIp: '198.51.100.7', reportedBy: null });
    const chip = screen.getByTestId('verdict-endpoints');
    expect(chip.textContent).toBe('192.0.2.10 → 198.51.100.7');
    expect(within(chip).queryByTestId('endpoint-on')).toBeNull();
  });
});

describe('alertEnds', () => {
  it('reads the display strings of an older server and drops the placeholder', () => {
    const ends = alertEnds({ host: '192.0.2.10', ip: '—' });
    expect(ends).toMatchObject({ src: '192.0.2.10', dst: null, on: null });
  });

  it('returns nothing when the alert names no end and no host', () => {
    expect(alertEnds({ host: '—', ip: '—', srcIp: null, dstIp: null, reportedBy: null })).toBeNull();
  });

  it('does not repeat a reporter that is one of the ends', () => {
    const ends = alertEnds({ host: 'x', ip: 'y', srcIp: '192.0.2.10', dstIp: null, reportedBy: '192.0.2.10' });
    expect(ends?.on).toBeNull();
  });
});
