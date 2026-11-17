// Red is for a confirmed threat or a failed write (K4, review 2026-11-12,
// console finding 13). The failed-run card had the border of a true positive
// card, the most frequent benign rule in Host context had a red bar, and the
// finding card of a false positive lead run had a pink-red border.
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

// The danger token, as a hex and as the rgb of its washes.
const RED = /f04438|240,\s*68,\s*56|fca5a5|244,\s*114,\s*182|f472b6|danger/i;

const base = (over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET INFO GNU/Linux APT User-Agent Outbound',
    kind: 'suricata',
    host: '10.20.30.5',
    ip: '10.40.50.7',
    verdict: 'false_positive',
    conf: 0.8,
    rationale: 'The traffic is a package update.',
    summary: [{ t: 'text', v: 'The host fetched packages.' }],
    status: 'complete',
    elapsedLabel: '1m',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

const mount = (i: Inv) =>
  render(
    <MemoryRouter>
      <Investigation inv={i} layout="page" />
    </MemoryRouter>,
  );

/** The class and the inline style of an element and of everything inside it. */
function paint(el: Element): string {
  return [el, ...Array.from(el.querySelectorAll('*'))]
    .map((n) => `${n.getAttribute('class') ?? ''} ${n.getAttribute('style') ?? ''}`)
    .join(' ');
}

describe('red marks a confirmed threat or a failed write only', () => {
  it('a failed run is grey with an amber icon', () => {
    mount(base({ status: 'error', verdict: 'untriaged', failure: { cause: 'x', permanent: false, kind: 'gateway' } }));
    const card = screen.getByTestId('failed-run-card');
    expect(paint(card)).not.toMatch(RED);
    expect(card.querySelector('.text-warn')).not.toBeNull();
  });

  it('a pipeline error panel is grey with an amber label', () => {
    mount(base({ verdict: 'needs_more_info', fallback: { phase: 'synth_first_round1', errorType: 'ModelHTTPError', hint: null } as Inv['fallback'] }));
    const panel = screen.getByTestId('pipeline-error-panel');
    expect(paint(panel)).not.toMatch(RED);
    expect(panel.querySelector('.text-warn')).not.toBeNull();
  });

  it('every Host context bar has one neutral color', () => {
    mount(
      base({
        hostContext: [
          { time: '', label: 'ET INFO GNU/Linux APT User-Agent Outbound', tone: 'critical', w: 100, sev: '279×' },
          { time: '', label: 'ET INFO ZIP file download', tone: 'low', w: 6, sev: '6×' },
        ],
      }),
    );
    const bars = screen.getAllByTestId('host-context-bar');
    expect(bars).toHaveLength(2);
    for (const bar of bars) {
      expect(bar.className).toContain('bg-sev-low');
      expect(paint(bar)).not.toMatch(RED);
    }
  });

  it('the finding card of a false positive run is neutral', () => {
    mount(
      base({
        kind: 'hunt',
        huntId: 'H1',
        promotedFinding: {
          ordinal: 0,
          label: 'F1',
          title: 'Inbound TCP probe from a listed address',
          hosts: [],
          attacker: null,
          victim: null,
          huntId: 'H1',
          huntTitle: 'Lead 53',
        },
      }),
    );
    expect(paint(screen.getByTestId('promoted-finding'))).not.toMatch(RED);
    expect(paint(screen.getByTestId('promoted-from-hunt'))).not.toMatch(RED);
  });

  it('control: a true positive verdict card keeps red', () => {
    const { container } = mount(base({ verdict: 'true_positive' }));
    const card = container.querySelector('[data-tour="investigation-verdict"]');
    expect(card).not.toBeNull();
    expect(paint(card!)).toMatch(/240,\s*68,\s*56|f04438/i);
  });
});
