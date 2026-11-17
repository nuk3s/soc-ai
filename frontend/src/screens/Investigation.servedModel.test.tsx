// The served model of a run (B4, review 2026-11-12). On 2026-11-03 the gateway
// served 42 of 84 verdicts from a fallback route, and two of them were wrong
// true positives. The report page named the configured model only, so the
// analyst could not see that a weaker model wrote the verdict.
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

const inv = (meta: Record<string, unknown>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'GPL SHELLCODE x86 setgid 0',
    kind: 'suricata',
    host: '192.0.2.1',
    ip: '—',
    verdict: 'true_positive',
    conf: 0.85,
    rationale: 'The payload is shellcode.',
    summary: [{ t: 'text', v: 'x' }],
    status: 'complete',
    elapsedLabel: '3m',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    meta: {
      model: 'analyst-main',
      ranBy: 'auto-triage:scheduler',
      ranAt: '2026-11-03T04:00:00+00:00',
      toolCalls: 2,
      pivots: 1,
      ...meta,
    },
  }) as unknown as Inv;

const mount = (i: Inv) =>
  render(
    <MemoryRouter>
      <Investigation inv={i} layout="page" />
    </MemoryRouter>,
  );

describe('the served model line', () => {
  it('names the model that served, marks a fallback route and names the asked model', () => {
    mount(
      inv({
        servedModel: 'qwen3.6-35b-temp-fallback',
        requestedModel: 'glm-5.3-flash',
        servedFallback: true,
      }),
    );
    const line = screen.getByTestId('served-model-line');
    expect(line.textContent).toBe(
      'qwen3.6-35b-temp-fallback. A fallback route served this investigation. The investigation asked for glm-5.3-flash.',
    );
    expect(screen.getByTestId('served-fallback-mark')).toBeTruthy();
  });

  it('control: two configured names on one backend have the line and no mark', () => {
    // The production shape: a call asked for a configured name that is not
    // the analyst model, and the gateway served that name.
    mount(
      inv({
        model: 'deepseek-v4-flash',
        servedModel: 'deepseek-v4-flash',
        requestedModel: 'deepseek-v4-flash',
        servedFallback: false,
      }),
    );
    expect(screen.getByTestId('served-model-line').textContent).toBe(
      'deepseek-v4-flash. The investigation asked for deepseek-v4-flash.',
    );
    expect(screen.queryByTestId('served-fallback-mark')).toBeNull();
  });

  it('names the served model alone when an older run recorded no asked model', () => {
    mount(inv({ servedModel: 'deepseek-v4-flash', requestedModel: null, servedFallback: false }));
    expect(screen.getByTestId('served-model-line').textContent).toBe('deepseek-v4-flash');
  });

  it('control: a run with no attribution reads not recorded and has no mark', () => {
    mount(inv({ servedModel: null, requestedModel: null, servedFallback: true }));
    expect(screen.getByTestId('served-model-line').textContent).toBe('not recorded');
    expect(screen.queryByTestId('served-fallback-mark')).toBeNull();
  });
});

// A model call that hit the output token limit ran again with low reasoning
// (B6). The line that names the model carries the mark.
describe('the low reasoning mark', () => {
  it('marks the model line of a run that used the low reasoning retry', () => {
    mount(inv({ lowReasoning: true }));
    expect(screen.getByTestId('model-line').textContent).toBe(
      'analyst-main. A model call ran again with low reasoning',
    );
    expect(screen.getByTestId('low-reasoning-mark')).toBeTruthy();
  });

  it('control: a run with no retry has no mark', () => {
    mount(inv({ lowReasoning: false }));
    expect(screen.getByTestId('model-line').textContent).toBe('analyst-main');
    expect(screen.queryByTestId('low-reasoning-mark')).toBeNull();
  });
});

