// The authorized activity of a run on its page. A run inside a scope keeps
// its true positive verdict and carries the mark, the label, the analyst and
// the expiry. A run outside a scope carries one line that names the part
// that failed. The control: a plain true positive carries neither, and it
// offers the button that starts a record.
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
  getActionScope: vi.fn().mockResolvedValue(null),
  getAuthorizedDraft: vi.fn().mockReturnValue(new Promise(() => {})),
}));

import { Investigation } from './Investigation';

const inv = (over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET EXPLOIT PHP php2shell Nested Empty File Control OOM (CVE-2026-109618)',
    kind: 'suricata',
    host: '10.50.0.26',
    ip: '10.40.0.164',
    verdict: 'true_positive',
    conf: 0.85,
    rationale: 'The source sent php2shell exploit requests.',
    summary: [{ t: 'text', v: 'The source sent php2shell exploit requests.' }],
    status: 'complete',
    elapsedLabel: '1m',
    actions: [
      {
        id: 'a0',
        title: 'Escalate to case',
        tag: 'escalate',
        rationale: 'Open a case for the exploit requests.',
      },
    ],
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

afterEach(cleanup);

describe('the authorized activity of a run', () => {
  it('shows the mark, the label, the analyst and the expiry, and keeps the verdict', () => {
    mount(
      inv({
        authorizationId: 3,
        authorization: {
          id: 3,
          label: 'php2shell test',
          state: 'active',
          expiresAt: '2026-11-20T10:00:00+00:00',
          by: 'casey',
        },
      }),
    );
    const note = screen.getByTestId('authorized-activity');
    expect(note.textContent).toContain('Authorized activity');
    expect(note.textContent).toContain(
      'php2shell test. casey recorded it. It expires on 2026-11-20 10:00 UTC. This investigation requests no case.',
    );
    expect(screen.getByRole('link', { name: 'Open its investigations.' }).getAttribute('href')).toBe(
      '/investigations?authorization=3&range=all',
    );
    // The verdict stays a true positive.
    expect(screen.getAllByText(/true positive/i).length).toBeGreaterThan(0);
    // A run that holds the mark cannot start a second record.
    expect(screen.queryByTestId('record-authorized')).toBeNull();
    // No action waits, and the flow strip names no write as the next step.
    expect(screen.getByText('0 actions wait for you')).toBeTruthy();
    expect(screen.getByTestId('flow-strip').textContent).not.toContain('Escalate to case');
    expect(screen.getByTestId('flow-strip').textContent).toContain('none requested');
  });

  it('says that a revoked authorization returns the run to normal handling', () => {
    mount(
      inv({
        authorizationId: 3,
        authorization: {
          id: 3,
          label: 'php2shell test',
          state: 'revoked',
          expiresAt: '2026-11-20T10:00:00+00:00',
          by: 'casey',
        },
      }),
    );
    expect(screen.getByTestId('authorized-activity').textContent).toContain(
      'An analyst revoked the authorized activity "php2shell test". This investigation gets normal handling.',
    );
    // The run can start a new record.
    expect(screen.getByTestId('record-authorized')).toBeTruthy();
  });

  it('shows the line of a run that is outside a scope', () => {
    mount(
      inv({
        outsideAuthorizedScope:
          'This activity is outside the authorized scope of php2shell test: the source is new.',
      }),
    );
    const line = screen.getByTestId('outside-authorized-scope');
    expect(line.textContent).toContain(
      'This activity is outside the authorized scope of php2shell test: the source is new.',
    );
    expect(line.textContent).toContain('This investigation gets normal handling.');
    expect(screen.queryByTestId('authorized-activity')).toBeNull();
  });

  it('control: a plain true positive has no mark and offers the record button', () => {
    mount(inv());
    expect(screen.queryByTestId('authorized-activity')).toBeNull();
    expect(screen.queryByTestId('outside-authorized-scope')).toBeNull();
    // The case request waits, and the flow strip names it.
    expect(screen.getByText('1 action waits for you')).toBeTruthy();
    expect(screen.getByTestId('flow-strip').textContent).toContain('Escalate to case');
    fireEvent.click(screen.getByTestId('record-authorized'));
    expect(screen.getByRole('dialog', { name: 'Record authorized activity' })).toBeTruthy();
  });

  it('offers no record button on a verdict other than true positive', () => {
    mount(inv({ verdict: 'false_positive' }));
    expect(screen.queryByTestId('record-authorized')).toBeNull();
    cleanup();
    mount(inv({ verdict: 'needs_more_info' }));
    expect(screen.queryByTestId('record-authorized')).toBeNull();
  });
});
