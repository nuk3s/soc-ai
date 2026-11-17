// The headline holds no field path; the path is a cited evidence chip
// (dogfood 2026-10-06, investigation C1). The control: a headline with no
// path shows no path chip.
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

const inv = (rationale: string): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'Rule',
    kind: 'suricata',
    host: '192.0.2.1',
    ip: '—',
    verdict: 'true_positive',
    conf: 0.9,
    rationale,
    summary: [{ t: 'text', v: 'x' }],
    status: 'complete',
    elapsedLabel: '1m',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
  }) as Inv;

const mount = (i: Inv) =>
  render(
    <MemoryRouter>
      <Investigation inv={i} layout="page" />
    </MemoryRouter>,
  );

describe('the headline', () => {
  it('moves a field path to a cited evidence chip', () => {
    const { container } = mount(inv('The exploit ran (alert.rule_metadata.metadata_tags).'));
    expect(screen.getByText('The exploit ran.')).toBeTruthy();
    // K1: the chip names the field in words, and the tooltip keeps the path.
    expect(screen.getByTestId('cited-path').textContent).toBe('Rule tags');
    expect(screen.getByTestId('cited-path').getAttribute('title')).toContain('alert.rule_metadata.metadata_tags');
    expect(container.querySelector('.text-\\[21px\\]')?.textContent).not.toContain('alert.rule_metadata');
  });

  it('control: a plain headline has no path chip', () => {
    mount(inv('The exploit ran.'));
    expect(screen.queryByTestId('cited-path')).toBeNull();
  });
});

// The headline is one sentence and the body never repeats it (review
// 2026-11-13, post wave 1).
describe('the headline and the body', () => {
  const SUMMARY =
    'Host ws-1 opened a TLS session to shop.example.test. The Zeek conn record shows state SF. ' +
    'Escalate and name the local application.';
  const lowered = (over: Partial<Inv> = {}): Inv =>
    ({ ...inv(SUMMARY), verdict: 'needs_more_info', summary: [{ t: 'text', v: SUMMARY }], ...over }) as Inv;

  it('prints the first sentence as the headline and the rest as the body', () => {
    const { container } = mount(lowered());
    expect(screen.getByTestId('verdict-headline').textContent).toBe(
      'Host ws-1 opened a TLS session to shop.example.test.',
    );
    expect(screen.getByTestId('verdict-body').textContent).toBe(
      'The Zeek conn record shows state SF. Escalate and name the local application.',
    );
    const text = container.textContent ?? '';
    expect(text.split('Host ws-1 opened a TLS session').length - 1).toBe(1);
  });

  it('shows the first line of the detail above the headline when the run states an impact', () => {
    const { container } = mount(
      lowered({ firstLine: 'An outbound TLS session to a developer domain.', impact: 'attempted' } as Partial<Inv>),
    );
    const line = screen.getByTestId('first-line');
    expect(line.textContent).toBe('An outbound TLS session to a developer domain.');
    const text = container.textContent ?? '';
    expect(text.indexOf('An outbound TLS session')).toBeLessThan(text.indexOf('Host ws-1 opened'));
  });

  it.each([
    ['succeeded', true],
    ['none', true],
    ['unknown', false],
    [null, false],
    [undefined, false],
  ])('shows the first line for the impact %s: %s', (impact, shown) => {
    // Polish review 2026-11-13: "True positive. Impact: not stated. ..." sat
    // under a verdict chip and a flow badge that state the same.
    mount(lowered({ firstLine: 'True positive. Impact: not stated. a to b.', impact } as Partial<Inv>));
    expect(screen.queryByTestId('first-line') !== null).toBe(shown);
  });

  it('control: a first line that is not text shows nothing', () => {
    mount(lowered({ firstLine: { v: 1 }, impact: 'succeeded' } as unknown as Partial<Inv>));
    expect(screen.queryByTestId('first-line')).toBeNull();
  });

  it('control: an analyst verdict keeps its whole note as the headline', () => {
    mount(
      lowered({
        rationale: 'Verdict set by analyst: a known scanner. The owner approved it.',
        resolution: { resolved_via: 'manual', resolved_by: 'analyst', original_verdict: 'true_positive' },
      } as Partial<Inv>),
    );
    expect(screen.getByTestId('verdict-headline').textContent).toBe(
      'Verdict set by analyst: a known scanner. The owner approved it.',
    );
  });
});
