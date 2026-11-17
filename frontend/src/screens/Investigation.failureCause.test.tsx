// A failed run states a plain cause first (K2, review 2026-11-12, console
// finding 14). Run 01M78JGQXMG95Q240SDG2SWTNV opened its card with
// "Recorded cause: status_code: 500, ... ssl.SSLContext object at 0x75b7...".
// The card now leads with one sentence for the class of the cause and the
// step the analyst can take. The raw error is behind a toggle.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv, InvestigationFailure } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
}));

import { Investigation } from './Investigation';

const RAW =
  "status_code: 500, model_name: glm-5.3-flash, body: {'message': 'Cannot connect to host " +
  "REDACTED:8888 ssl:<ssl.SSLContext object at 0x75b70ee58c30>'}";
const HINT = 'the LLM gateway could not reach its model backend. Check the serving engine. Then retry.';

const failed = (failure: InvestigationFailure | null, over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET INFO Observed Certificate',
    kind: 'suricata',
    host: '10.20.30.5',
    ip: '10.40.50.7',
    verdict: 'untriaged',
    conf: 0,
    rationale: '',
    summary: [],
    status: 'error',
    elapsedLabel: '7s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    failure,
    ...over,
  }) as Inv;

const mount = (i: Inv) =>
  render(
    <MemoryRouter>
      <Investigation inv={i} layout="page" />
    </MemoryRouter>,
  );

const CASES: Array<[string, string, string]> = [
  ['gateway', 'The model gateway did not answer. The investigation has no verdict.', 'Re-run it when the gateway answers again.'],
  ['token_limit', 'The model hit its output limit before it wrote a verdict.', 'Re-run it to try again.'],
  ['time_limit', 'The investigation hit its time limit before it reached a verdict.', 'Re-run it to try again.'],
  ['grid', 'The grid did not answer. The investigation has no verdict.', 'Re-run it when the grid answers again.'],
  ['other', 'The investigation stopped on an error before it reached a verdict.', 'Re-run it to try again.'],
];

describe('the failed-run card', () => {
  it.each(CASES)('leads with the plain cause of the class %s', (kind, cause, action) => {
    const { container } = mount(failed({ cause: RAW, hint: HINT, permanent: false, kind }));
    const text = container.textContent ?? '';
    expect(text).toContain(`${cause} ${action}`);
    // The raw error is behind the toggle.
    expect(text).not.toContain('SSLContext');
    expect(screen.queryByTestId('failure-cause')).toBeNull();
    expect(screen.getByRole('button', { name: 'Show the technical detail' })).toBeTruthy();
  });

  it('shows the raw error and the hint as a sentence after the toggle', () => {
    mount(failed({ cause: RAW, hint: HINT, permanent: false, kind: 'gateway' }));
    fireEvent.click(screen.getByRole('button', { name: 'Show the technical detail' }));
    expect(screen.getByTestId('failure-cause').textContent).toContain('ssl.SSLContext object at 0x75b70ee58c30');
    expect(screen.getByText(/^The LLM gateway could not reach its model backend\./)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Hide the technical detail' }));
    expect(screen.queryByTestId('failure-cause')).toBeNull();
  });

  it('reads a class it does not know as other', () => {
    const { container } = mount(failed({ cause: 'x', permanent: false, kind: 'quota' }));
    expect(container.textContent).toContain('The investigation stopped on an error before it reached a verdict.');
  });

  it('control: a permanent cause advises no re-run', () => {
    const { container } = mount(failed({ cause: 'alert not found: ev-1', permanent: true, kind: 'other' }));
    const text = container.textContent ?? '';
    expect(text).toContain('A new investigation cannot change the recorded cause.');
    expect(text).not.toContain('Re-run it');
  });

  it('control: a run with no recorded cause says so and has no toggle', () => {
    const { container } = mount(failed(null));
    expect(container.textContent).toContain('soc-ai recorded no cause.');
    expect(screen.queryByRole('button', { name: 'Show the technical detail' })).toBeNull();
  });
});
