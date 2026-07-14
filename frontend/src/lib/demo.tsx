// Demo-mode plumbing. One open (pre-auth) GET /api/v1/demo-status on shell
// mount decides whether the honesty banner and the recorded-run chips render.
//
// Fail-soft by design, same contract as useUpdateCheck: any fetch problem
// (backend down, non-demo deploy, an older backend without the endpoint) just
// means "not a demo" — no banner, no console noise. Raw fetch rather than
// lib/api's request() on purpose: request() redirects to the login page on a
// 401, and this probe must never navigate.
import { createContext, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';

const DemoCtx = createContext(false);

/** Fetch the backend's demo flag once (fail-soft to false). The two route
 *  roots — AppShell and Login — each own a call; AppShell shares its result
 *  with descendants via DemoProvider. */
export function useDemoStatus(): boolean {
  const [demo, setDemo] = useState(false);
  useEffect(() => {
    let alive = true;
    const probe = async () => {
      try {
        const res = await fetch('/api/v1/demo-status', {
          headers: { Accept: 'application/json' },
        });
        if (!res.ok) return;
        const body = (await res.json()) as { demo?: boolean };
        if (alive && body.demo === true) setDemo(true);
      } catch {
        // fail-soft: unreachable backend / missing endpoint → not a demo
      }
    };
    void probe();
    return () => {
      alive = false;
    };
  }, []);
  return demo;
}

export function DemoProvider({ demo, children }: { demo: boolean; children: ReactNode }) {
  return <DemoCtx.Provider value={demo}>{children}</DemoCtx.Provider>;
}

/** True when this deployment is the public demo (SOC_AI_DEMO on the backend). */
export function useDemo(): boolean {
  return useContext(DemoCtx);
}

/** The one honest note a mutating action shows in the read-only demo, in place
 *  of firing a doomed write and surfacing a raw error. Reused verbatim by every
 *  guarded handler (ack/escalate/assign, config save, action/override). */
export const DEMO_ACTION_NOTE =
  'Not available in the read-only demo — in a live deployment this would run for real.';

/** The single demo-guard decision, shared so a handler can't drift: returns the
 *  note to show (and the caller must return WITHOUT its network write) when this
 *  is the read-only demo, else null (live path proceeds unchanged). */
export function demoBlocked(demo: boolean): string | null {
  return demo ? DEMO_ACTION_NOTE : null;
}

/** The banner's fixed height (px) — hosts give up exactly this much
 *  (`calc(100vh - DEMO_BANNER_H px)`) so it pins without overlap or shift. */
export const DEMO_BANNER_H = 36;

/** The pinned, non-dismissible honesty banner. One definition so the copy
 *  can't drift between the shell and the login screen (the two route roots). */
export function DemoBanner() {
  return (
    <div
      role="status"
      className="flex items-center justify-center border-b px-4 text-center text-[12.5px] font-medium text-text-2"
      style={{ height: DEMO_BANNER_H, borderColor: 'rgba(75,139,245,.4)', background: '#0e1117' }}
    >
      Demo — these investigations were run by soc-ai and recorded. Nothing here is live.
    </div>
  );
}
