// Task 6 — honest "not in the demo" strips. A mutating action button in the
// read-only demo must show DEMO_ACTION_NOTE on the screen's existing inline
// strip and NEVER fire the network write. The guard is one shared helper
// (`demoBlocked`) wired through the real DemoProvider → useDemo chain, so this
// tests the actual decision the ack/escalate/save handlers make — not a copy.
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { DEMO_ACTION_NOTE, DemoProvider, demoBlocked, useDemo } from '../lib/demo';

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
