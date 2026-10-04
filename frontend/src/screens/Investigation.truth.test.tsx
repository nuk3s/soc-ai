// The investigation page says what the run recorded (fleet dogfood 2026-10-01).
//
// P2  a needs_more_info verdict read "VERDICT SETTLED. TAKE ACTION." and never
//     offered Request more info, because every prod run had no open questions.
// P3  cited document ids were plain text everywhere on the page.
// P4  Re-run stayed live during a run, and a click started a duplicate.
// P10 the running panel, the meta panel and the timeline counted tool calls
//     three different ways.
// P11 the fallback headline was the exception text.
// RL11 / D1 the failed-run copy guessed a stall while the cause was recorded,
//     and advised a re-run for a cause no re-run can change.
// P16 "1 steps", the untriaged placeholder card, an FP starter question that
//     asks the chat to argue against the verdict.
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

const startHunt = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  startHunt,
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
}));

import { FALLBACK_HEADLINE, Investigation, RERUN_BUSY_REASON, starterQuestions } from './Investigation';

const ES_ID = 'UbhH2KABxYz0123456_q';

const baseInv = (over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET SCAN Potential SSH Scan',
    kind: 'suricata',
    host: '192.0.2.10',
    ip: '198.51.100.7',
    verdict: 'false_positive',
    conf: 0.8,
    rationale: 'Routine scan from the vulnerability scanner.',
    summary: [{ t: 'text', v: 'The scanner runs every night.' }],
    status: 'complete',
    elapsedLabel: '1m 4s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

const mount = (over: Partial<Inv> = {}, layout: 'page' | 'drawer' = 'page') =>
  render(
    <MemoryRouter>
      <Investigation inv={baseInv(over)} layout={layout} />
    </MemoryRouter>,
  );

beforeEach(() => {
  startHunt.mockReset();
  startHunt.mockResolvedValue('INV-NEW');
});

describe('a needs_more_info verdict (P2)', () => {
  it('offers Request more info and Resolve in chat with no open questions', () => {
    mount({ verdict: 'needs_more_info', openQuestions: [] });
    expect(screen.getByRole('button', { name: /request more info/i })).toBeTruthy();
    expect(screen.getByRole('button', { name: /resolve in chat/i })).toBeTruthy();
    expect(screen.queryByText(/Verdict settled\. Take action\./i)).toBeNull();
    expect(screen.queryByRole('button', { name: /^acknowledge$/i })).toBeNull();
  });

  it('still offers the settled bar on a committed verdict', () => {
    // Negative control: the fix must not take the bar off a real verdict.
    mount({ verdict: 'false_positive' });
    expect(screen.getByText(/Verdict settled\. Take action\./i)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /request more info/i })).toBeNull();
  });
});

describe('cited documents (P3)', () => {
  it('renders a cited id in the headline and the summary as a control', () => {
    mount({
      rationale: `The scanner touched the host (${ES_ID}).`,
      summary: [{ t: 'text', v: `See ${ES_ID} for the flow.` }],
      citations: [{ text: ES_ID, kind: 'id', target: ES_ID, resolved: true }],
    });
    // Headline, summary and the cited-evidence row: three controls, no plain id.
    expect(screen.getAllByRole('button', { name: ES_ID })).toHaveLength(3);
    expect(within(screen.getByTestId('cited-evidence')).getByRole('button', { name: ES_ID })).toBeTruthy();
  });

  it('leaves a 20-letter word as text', () => {
    // Negative control on the path the shape test could miss: a word with
    // the length of an id.
    mount({ rationale: 'internationalization of the scanner config' });
    expect(screen.queryByRole('button', { name: 'internationalization' })).toBeNull();
  });
});

describe('Re-run during a run (P4)', () => {
  it('is disabled with a reason while the run is in flight', () => {
    mount({ status: 'investigating', verdict: 'untriaged', conf: 0 }, 'drawer');
    const btn = screen.getByRole('button', { name: /re-run investigation/i });
    expect(btn).toBeDisabled();
    expect(btn).toHaveAttribute('title', RERUN_BUSY_REASON);
    fireEvent.click(btn);
    expect(startHunt).not.toHaveBeenCalled();
  });

  it('is enabled on a finished run', () => {
    mount({ status: 'complete' });
    const btn = screen.getByRole('button', { name: /re-run investigation/i });
    expect(btn).not.toBeDisabled();
  });
});

describe('one tool-call count (P10)', () => {
  const timeline = [
    { id: 'e1', group: 'Prefetch & pivots', title: 'Host dossier: asset context for 2 hosts', time: '', detail: '' },
    { id: 'e2', group: 'Tool calls', title: 'Event search: 4 matches', time: '', detail: '' },
    { id: 'e3', group: 'Tool calls', title: 'Cases: no results', time: '', detail: '' },
    { id: 'e4', group: 'Decision', title: 'Auto-acknowledge skipped: high stakes', time: '', detail: '' },
  ] as Inv['timeline'];

  it('counts the Tool calls rows in the running panel', () => {
    // meta says 0: the old drawer printed it while a tool row was on screen.
    const meta = { model: 'm', ranBy: 'x', ranAt: '', toolCalls: 0, pivots: 0 };
    const { container } = mount(
      { status: 'investigating', verdict: 'untriaged', conf: 0, timeline, meta },
      'drawer',
    );
    expect(container.textContent).toMatch(/tool calls\s*2/);
  });

  it('counts the same rows in the meta panel', () => {
    const meta = { model: 'm', ranBy: 'x', ranAt: '', toolCalls: 3, pivots: 0 };
    mount({ timeline, meta });
    expect(screen.getByText('tool calls').nextElementSibling).toHaveTextContent(/^2$/);
  });
});

describe('a pipeline fallback headline (P11)', () => {
  const raw =
    'Synth-first pipeline fallback: synth_first_round1 raised TimeoutError. The alert is recorded as needs_more_info.';

  it('shows a plain line with the marker', () => {
    const { container } = mount({
      verdict: 'needs_more_info',
      rationale: raw,
      fallback: { provenance: 'pipeline_fallback' },
    });
    expect(screen.getByText(FALLBACK_HEADLINE)).toBeTruthy();
    expect(container.textContent).not.toContain('raised TimeoutError');
  });

  it('shows a plain line without the marker', () => {
    const { container } = mount({ kind: 'hunt', verdict: 'needs_more_info', rationale: raw });
    expect(screen.getByText(FALLBACK_HEADLINE)).toBeTruthy();
    expect(container.textContent).not.toContain('Synth-first pipeline fallback');
  });
});

describe('a failed run (RL11, RD13, D1)', () => {
  it('shows a permanent cause and does not advise a re-run', () => {
    const { container } = mount({
      status: 'error',
      verdict: 'untriaged',
      failure: { cause: 'alert not found: ev-1', permanent: true },
    });
    expect(screen.getByTestId('failure-cause')).toHaveTextContent('alert not found: ev-1');
    expect(container.textContent).not.toContain('may have stalled');
    expect(container.textContent).not.toContain('Re-run it to try again');
    // Only the toolbar keeps its button. The panel offers none.
    expect(screen.getAllByRole('button', { name: /re-run investigation/i })).toHaveLength(1);
  });

  it('keeps the re-run advice for a cause a re-run can change', () => {
    const { container } = mount({
      status: 'error',
      verdict: 'untriaged',
      failure: { cause: 'synth timed out', permanent: false },
    });
    expect(container.textContent).toContain('Re-run it to try again.');
    expect(screen.getAllByRole('button', { name: /re-run investigation/i })).toHaveLength(2);
  });

  it('links the later run that replaced this one', () => {
    const { container } = mount({ status: 'error', verdict: 'untriaged', supersededBy: 'INV-LATER' });
    expect(screen.getByTestId('superseded-by')).toHaveTextContent('A later run replaced this one.');
    expect(screen.getByRole('link', { name: 'Open the later run' })).toHaveAttribute(
      'href',
      '/investigation/INV-LATER',
    );
    expect(container.textContent).not.toContain('try again');
  });
});

describe('small truths (P16)', () => {
  it('counts one step as "1 step"', () => {
    mount({ timeline: [{ id: 'e1', group: 'Decision', title: 'Verdict', time: '', detail: '' }] });
    expect(screen.getByText(/^1 step · /)).toBeTruthy();
  });

  it('shows no placeholder verdict card while a run is in flight', () => {
    const { container } = mount({ status: 'investigating', verdict: 'untriaged', conf: 0 });
    expect(container.textContent).not.toMatch(/0\.00\s*confidence/i);
    expect(screen.getByText('Investigating…')).toBeTruthy();
  });

  it('picks starter questions that fit the verdict', () => {
    expect(starterQuestions('false_positive')).not.toContain('Why not a false positive?');
    expect(starterQuestions('false_positive')[0]).toBe('Why not a true positive?');
    expect(starterQuestions('true_positive')[0]).toBe('Why not a false positive?');
  });
});
