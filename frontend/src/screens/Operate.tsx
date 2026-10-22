import { ArrowRight, BookOpen, Gauge, History, ShieldCheck, Stethoscope, TrendingUp, Wrench } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { EscalationLedgerPanel } from '../components/EscalationLedgerPanel';
import { HuntCatalogPanel } from '../components/HuntCatalogPanel';
import { Panel, PanelHeader } from '../components/Panel';
import { StatusDependenciesPanel } from '../components/StatusDependenciesPanel';
import { StatusJobsPanel } from '../components/StatusJobsPanel';

// ---------------------------------------------------------------------------
// Operate — the hub for the operator's loop, as opposed to the analyst's
// (Sidebar.tsx's own framing for the nav group this screen anchors): prove
// the model is fit, prove the verdicts held up, prove the audit chain is
// intact, replay history, read the doctor's view, and reach the runbooks
// that ground every verdict. Six links and their one-line purpose, nothing
// else.
//
// The six link cards fetch nothing and poll nothing (YAGNI, per the Wave-2
// plan): the Dashboard's persistent setup-health card (preflight endpoints)
// already owns "is anything wrong right now", and these cards only orient to
// WHERE each proof lives. Operate.test.tsx's poller guard pins that for every
// api fn one of them could be tempted to reach for.
//
// The exceptions are the live panels above them, and they are here for the
// same reason: each answers a question about unattended machinery that has no
// other owner in the app.
//
// The dependency block and the job list come first (H1-D14, R5-I4). The page
// showed no dependency state and listed one unattended loop of six, so an
// operator who opened it during an outage read green analytics rows and no
// word about the grid. The dependency block reads GET /health, the same probe
// the header pill reads. The job list reads the existing status route of each
// job, plus GET /audit/verify-schedule. Both poll on the 5-minute cadence.
//
// The hunt catalog runs unattended — a scheduler sweep with no model call and,
// when nothing fires, no visible trace anywhere else — so this is the one page
// that has to say whether it is actually running, whether any spec has gone
// blind, and whether the loop is even switched on. Reads GET /hunt-catalog on
// a 5-minute cadence.
//
// The escalation ledger is the same shape of silence one layer down. An
// escalate claims its alert before opening the case, and a claim that never
// gets an answer stays open forever, refusing every future escalate of that
// alert. Reconciliation only happens on a later group press covering the same
// alert, so a claim whose alert has left the queue is permanent — and until
// that panel, invisible outside the database. Reads GET /escalations/stranded
// on the same cadence. The guard in Operate.test.tsx admits the panels' reads
// by name, once each per 5-minute tick, and nothing else.
// ---------------------------------------------------------------------------

interface CardDef {
  title: string;
  purpose: string;
  to: string;
  // Pre-instantiated (HuntDetail.tsx's STEP_ICON idiom), not a component
  // reference — sidesteps re-typing lucide's exact prop signature.
  icon: ReactNode;
}

/**
 * Card targets — each VERIFIED against the running Config/App code rather
 * than assumed (2026-08-19, branch head fe12fb6):
 *
 * - Model fitness → `/config#agent`. `analyst_model` is `section="Agent"`
 *   (soc_ai/store/config_overrides.py); its inline fitness chip + battery
 *   panel (ModelFitnessChip / ModelBatteryPanel, Config.tsx ~1155-1250)
 *   render as part of that group's row. `idFor('Agent')` in configLayout.ts
 *   slugs to `agent` with no RESERVED_IDS collision, so `/config#agent`
 *   opens exactly the section hosting the battery.
 * - Verdict quality → `/config#quality`. SECTION_ORDER/SECTION_PARENTS group
 *   `"Quality"` under Models & Reasoning specifically because the nightly
 *   micro-eval measures what Agent/Oracle configure; `idFor('Quality')` →
 *   `quality`, uncontested.
 * - Audit chain → `/config#diagnostics`. `diagnostics` now hosts the "Verify
 *   audit chain" control (Config.tsx's diagnosticsSection, calling
 *   `GET /config/audit/verify-chain`) alongside Test ES/Test LLM — this was
 *   originally a documented nearest-neighbor fallback (no dedicated control
 *   existed yet); superseded once the control landed there directly, so
 *   it's now the exact anchor.
 * - Diagnostics → `/config#diagnostics`. `diagnostics` is a standalone
 *   PANELS entry in configLayout.ts (RESERVED_IDS) — a stable anchor.
 * - Backtest / Runbooks → `/backtest` / `/runbooks`, existing top-level
 *   routes (App.tsx).
 */
const CARD_DEFS: CardDef[] = [
  {
    title: 'Model fitness',
    purpose: 'Measure if the model is fit for triage.',
    to: '/config#agent',
    icon: <Gauge size={16} />,
  },
  {
    title: 'Verdict quality',
    purpose: 'Measure the quality of the verdicts. The nightly eval shows the trend.',
    to: '/config#quality',
    icon: <TrendingUp size={16} />,
  },
  {
    title: 'Audit chain',
    purpose: 'Verify that the tamper-evident record is intact.',
    to: '/config#diagnostics',
    icon: <ShieldCheck size={16} />,
  },
  {
    title: 'Backtest',
    purpose: 'Replay closed alerts through the current triage.',
    to: '/backtest',
    icon: <History size={16} />,
  },
  {
    title: 'Diagnostics',
    purpose: 'Run the setup checks and read the results.',
    to: '/config#diagnostics',
    icon: <Stethoscope size={16} />,
  },
  {
    title: 'Runbooks',
    purpose: 'Write the procedures that the model cites in a verdict.',
    to: '/runbooks',
    icon: <BookOpen size={16} />,
  },
];

/** Exported for the table-driven test — title/purpose/to only; the icon is a
 * render-time concern, not part of the data shape the test asserts on. */
export const CARDS: { title: string; purpose: string; to: string }[] = CARD_DEFS.map(
  ({ title, purpose, to }) => ({ title, purpose, to }),
);

export function Operate() {
  return (
    <div className="px-[22px] pb-[60px] pt-5">
      {/* page header — same register as Backtest.tsx's */}
      <div data-tour="status-header" className="mb-5">
        <div className="flex items-center gap-2">
          <Wrench size={19} className="text-accent" />
          {/* "Status": the group and its first page both read "Operate". */}
          <div className="text-[20px] font-semibold tracking-[-.015em]">Status</div>
        </div>
        <div className="mt-0.5 max-w-[720px] text-[13px] text-dim">
          This page shows the state of the automatic work. Check that the grid and the model
          gateway answer. Check that each job and each analytic runs. Check that each escalation
          has an answer. Open the checks of the model and the audit chain.
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {/* First, because every job below needs them: is the grid up, and
            does the model gateway answer? Then the jobs themselves. */}
        {/* Each wrapper is the full-width grid item and holds the anchor of
            the page tour. A Panel takes no attribute. The panel inside keeps
            its own md:col-span-2, which does nothing outside a grid. */}
        <div data-tour="status-dependencies" className="md:col-span-2">
          <StatusDependenciesPanel />
        </div>
        <div data-tour="status-jobs" className="md:col-span-2">
          <StatusJobsPanel />
        </div>
        {/* Full-width, in the same grid as the link cards rather than a
            block of its own: the reason an operator comes here ("is it
            running?") is answered before the orientation links, while the
            page keeps one gutter rhythm instead of two stacked containers. */}
        <HuntCatalogPanel />
        {/* Second, and full-width for the same reason: a stranded claim is an
            alert that cannot be escalated, which is a live operational fact
            and not an orientation link. */}
        <div data-tour="status-escalations" className="md:col-span-2">
          <EscalationLedgerPanel />
        </div>
        {CARD_DEFS.map(({ title, purpose, to, icon }) => (
          <Panel key={title}>
            <PanelHeader icon={icon} title={title} />
            <div className="flex flex-col gap-3 px-[15px] py-3.5">
              <div className="text-[12.5px] leading-[1.5] text-dim">{purpose}</div>
              <Link
                to={to}
                aria-label={`Open ${title}`}
                className="inline-flex w-fit items-center gap-1.5 rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent"
              >
                Open
                <ArrowRight size={12} />
              </Link>
            </div>
          </Panel>
        ))}
      </div>
    </div>
  );
}
