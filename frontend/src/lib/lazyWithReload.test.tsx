// lazyWithReload guards deploy resilience: a stale open tab that lazy-imports
// a replaced (content-hashed) chunk must heal itself with EXACTLY one reload,
// and a genuinely-broken server must reach the error boundary instead of
// reload-looping. These tests pin the one-shot flag protocol.
//
// window.location.reload is spy-able here because the vitest environment is
// happy-dom (jsdom's Location is WHATWG-unforgeable — see vite.config.ts).
import { render, screen, waitFor } from '@testing-library/react';
import { Component, Suspense } from 'react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { lazyWithReload } from './lazyWithReload';

const FLAG = 'socai-chunk-reload';

// Minimal local boundary — this suite pins that the error RETHROWS; what the
// real card looks like is ErrorBoundary.test.tsx's job.
class Catcher extends Component<{ children: ReactNode }, { message: string | null }> {
  state = { message: null };
  static getDerivedStateFromError(error: Error) {
    return { message: error.message };
  }
  render() {
    return this.state.message ? <div>caught: {this.state.message}</div> : this.props.children;
  }
}

let reload: ReturnType<typeof vi.fn>;

beforeEach(() => {
  sessionStorage.clear();
  reload = vi.fn();
  vi.spyOn(window.location, 'reload').mockImplementation(reload);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('lazyWithReload', () => {
  it('first import failure sets the one-shot flag and reloads, holding the Suspense fallback', async () => {
    const Lazy = lazyWithReload(() => Promise.reject(new Error('404 stale chunk')));
    render(
      <Suspense fallback={<div>loading…</div>}>
        <Lazy />
      </Suspense>,
    );
    await waitFor(() => expect(reload).toHaveBeenCalledTimes(1));
    expect(sessionStorage.getItem(FLAG)).toBe('1');
    // The importer never resolves after triggering the reload, so nothing
    // stale (or error-shaped) flashes while the reload is in flight.
    expect(screen.getByText('loading…')).toBeInTheDocument();
  });

  it('second failure (flag already set) rethrows to the error boundary — no reload loop', async () => {
    sessionStorage.setItem(FLAG, '1');
    // React logs boundary-caught errors; keep the test output clean.
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const Lazy = lazyWithReload(() => Promise.reject(new Error('server really down')));
    render(
      <Catcher>
        <Suspense fallback={<div>loading…</div>}>
          <Lazy />
        </Suspense>
      </Catcher>,
    );
    expect(await screen.findByText('caught: server really down')).toBeInTheDocument();
    expect(reload).not.toHaveBeenCalled();
  });

  it('a successful import clears the flag (re-arms auto-heal for the next deploy)', async () => {
    sessionStorage.setItem(FLAG, '1');
    const Lazy = lazyWithReload(() =>
      Promise.resolve({ default: () => <div>screen loaded</div> }),
    );
    render(
      <Suspense fallback={<div>loading…</div>}>
        <Lazy />
      </Suspense>,
    );
    expect(await screen.findByText('screen loaded')).toBeInTheDocument();
    expect(sessionStorage.getItem(FLAG)).toBeNull();
    expect(reload).not.toHaveBeenCalled();
  });
});
