// Task 6 — honest "not in the demo" strips. A mutating action button in the
// read-only demo must show DEMO_ACTION_NOTE on the screen's existing inline
// strip and NEVER fire the network write. The guard is one shared helper
// (`demoBlocked`) wired through the real DemoProvider → useDemo chain, so this
// tests the actual decision the ack/escalate/save handlers make — not a copy.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { DEMO_ACTION_NOTE, DemoProvider, demoBlocked, useDemo } from '../lib/demo';
import { ShellProvider } from '../shell/ShellContext';

// F38 — background poll pause while the drawer is open. A single group with an
// existing investigation (invId) so "Open investigation" is on the row without
// needing to fake a hunt round-trip.
const POLL_GROUP = vi.hoisted(() => ({
  id: 'g1',
  name: 'ET SCAN Test Detection',
  kind: 'suricata',
  sev: 'high',
  count: 3,
  verdict: 'true_positive',
  conf: 0.9,
  latest: '2m ago',
  inherited: false,
  events: [],
  invId: 'INV-1',
}));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue([POLL_GROUP]),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
  // The drawer's own investigation fetch never needs to resolve for this test —
  // leaving it pending keeps the (heavy) Investigation report out of the tree.
  getInvestigation: vi.fn(() => new Promise(() => {})),
  assignAlert: vi.fn().mockResolvedValue({ ok: true }),
}));

import { Alerts } from './Alerts';
import { assignAlert, getAlerts } from '../lib/api';

// Pinned literally (not imported) so a copy edit to the note can't self-approve.
const NOTE =
  'Not available in the read-only demo — in a live deployment this would run for real.';

describe('demoBlocked', () => {
  it('returns the note in demo mode', () => {
    expect(demoBlocked(true)).toBe(NOTE);
    expect(DEMO_ACTION_NOTE).toBe(NOTE);
  });

  it('returns null on a live deployment (no block)', () => {
    expect(demoBlocked(false)).toBeNull();
  });
});

// A miniature of every guarded handler: read useDemo(), consult demoBlocked(),
// and on a block set the inline strip + return WITHOUT the network mutation.
function EscalateControl({
  onMutate,
  onStrip,
}: {
  onMutate: () => void;
  onStrip: (m: string) => void;
}) {
  const demo = useDemo();
  return (
    <button
      onClick={() => {
        const note = demoBlocked(demo);
        if (note) {
          onStrip(note);
          return;
        }
        onMutate();
      }}
    >
      Escalate
    </button>
  );
}

describe('demo action guard', () => {
  it('shows the note and does NOT fire the mutation in demo mode', () => {
    const onMutate = vi.fn();
    const onStrip = vi.fn();
    render(
      <DemoProvider demo>
        <EscalateControl onMutate={onMutate} onStrip={onStrip} />
      </DemoProvider>,
    );
    fireEvent.click(screen.getByText('Escalate'));
    expect(onStrip).toHaveBeenCalledWith(NOTE);
    expect(onMutate).not.toHaveBeenCalled();
  });

  it('fires the mutation normally on a live (non-demo) deployment', () => {
    const onMutate = vi.fn();
    const onStrip = vi.fn();
    render(
      <DemoProvider demo={false}>
        <EscalateControl onMutate={onMutate} onStrip={onStrip} />
      </DemoProvider>,
    );
    fireEvent.click(screen.getByText('Escalate'));
    expect(onMutate).toHaveBeenCalledTimes(1);
    expect(onStrip).not.toHaveBeenCalled();
  });
});

// The Config admin panel guards the same way, reusing each handler's own error
// surface (setUserError, setIdentError, setTokenMsg, …). This mirrors the
// createUser handler: demo → the note lands on the existing error strip and the
// POST never fires.
function CreateUserControl({
  createUser,
  setUserError,
}: {
  createUser: () => void;
  setUserError: (m: string) => void;
}) {
  const demo = useDemo();
  return (
    <button
      onClick={() => {
        const note = demoBlocked(demo);
        if (note) {
          setUserError(note);
          return;
        }
        createUser();
      }}
    >
      Create user
    </button>
  );
}

describe('config admin action guard', () => {
  it('shows the note on the users error strip and does NOT POST in demo mode', () => {
    const createUser = vi.fn();
    const setUserError = vi.fn();
    render(
      <DemoProvider demo>
        <CreateUserControl createUser={createUser} setUserError={setUserError} />
      </DemoProvider>,
    );
    fireEvent.click(screen.getByText('Create user'));
    expect(setUserError).toHaveBeenCalledWith(NOTE);
    expect(createUser).not.toHaveBeenCalled();
  });

  it('creates the user normally on a live deployment', () => {
    const createUser = vi.fn();
    const setUserError = vi.fn();
    render(
      <DemoProvider demo={false}>
        <CreateUserControl createUser={createUser} setUserError={setUserError} />
      </DemoProvider>,
    );
    fireEvent.click(screen.getByText('Create user'));
    expect(createUser).toHaveBeenCalledTimes(1);
    expect(setUserError).not.toHaveBeenCalled();
  });
});

// F38 — useAsync's background-poll interval calls `pauseWhen` on whatever
// closure was live when its effect last ran; that effect's deps don't include
// `drawerId`, so a plain `() => !!drawerId` freezes at the drawer state from
// mount instead of tracking it live (the exact gotcha every other pauseWhen
// call site in this codebase routes around with a ref). Drive the real
// interval callback directly (captured off `setInterval`, called by hand)
// rather than waiting out the 10s in real time.
describe('alerts grid background poll (F38)', () => {
  it('pauses the 10s poll once the investigation drawer is open', async () => {
    const intervalSpy = vi.spyOn(window, 'setInterval');
    try {
      render(
        <MemoryRouter initialEntries={['/alerts']}>
          <ShellProvider>
            <Alerts />
          </ShellProvider>
        </MemoryRouter>,
      );

      // Initial foreground fetch, then the row is on screen.
      await screen.findByLabelText('Open investigation');
      expect(getAlerts).toHaveBeenCalledTimes(1);

      const pollCall = intervalSpy.mock.calls.find((c) => c[1] === 10000);
      expect(pollCall).toBeTruthy();
      const poll = pollCall![0] as () => void;

      // Drawer closed — a poll tick should still fetch.
      poll();
      expect(getAlerts).toHaveBeenCalledTimes(2);

      // Open the drawer (no dep of the outer useAsync effect changes).
      fireEvent.click(screen.getByLabelText('Open investigation'));
      await screen.findByLabelText('Close');

      // A poll tick while the drawer is open must be skipped.
      poll();
      expect(getAlerts).toHaveBeenCalledTimes(2);
    } finally {
      intervalSpy.mockRestore();
    }
  });
});

// F39 — the owner-avatar "+" (assign to me), the owner avatar (release), and
// Review/Done all reuse assignAlert with no .catch, unlike every sibling write
// in this file (ackOneGroup, escalateOneGroup, the bulk assign/ack blocks) —
// a failed request silently left the row unchanged with no analyst feedback.
describe('assignAlert write paths surface a failure instead of failing silently (F39)', () => {
  it('shows a failure message on the ack strip when "Assign to me" rejects', async () => {
    vi.mocked(assignAlert).mockRejectedValueOnce(new Error('network down'));
    render(
      <MemoryRouter initialEntries={['/alerts']}>
        <ShellProvider>
          <Alerts />
        </ShellProvider>
      </MemoryRouter>,
    );

    const assignBtn = await screen.findByTitle('Assign to me');
    fireEvent.click(assignBtn);

    await screen.findByText(`Failed to assign ${POLL_GROUP.name}`);
  });
});
