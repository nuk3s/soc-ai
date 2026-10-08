import { History } from 'lucide-react';

// ---- backtest replay chip ----------------------------------------------------
// A backtest replays the agent over alerts an analyst already closed and
// scores the verdicts. Each replay is a stored investigation, so it can appear
// on the Investigations list and has its own page. On the range one week held
// 14 true positives, and 12 of them were replays with no mark (dogfood
// 2026-10-06). The chip marks a replay wherever the console shows one. The
// server leaves replays out of the list and the counts by default.

/** The actor a backtest replay records in `ranBy`. The server writes it
 *  (soc_ai.store.investigations.BACKTEST_ACTOR). */
export const BACKTEST_ACTOR = 'backtest';

/** Whether the run is a backtest replay, from the actor that started it. */
export function isBacktestReplay(ranBy: string | null | undefined): boolean {
  return ranBy === BACKTEST_ACTOR;
}

export const CHIP_BACKTEST_REPLAY =
  'A backtest ran this investigation on an alert that an analyst closed before. ' +
  'The replay measures the model. It writes nothing to Security Onion, forms no lead ' +
  'and sends no notification. Its actions are not executable.';

export function BacktestReplayChip({ testId }: { testId?: string }) {
  return (
    <span
      data-testid={testId ?? 'backtest-replay-chip'}
      title={CHIP_BACKTEST_REPLAY}
      className="inline-flex flex-none items-center gap-1 whitespace-nowrap rounded-badge border border-border-2 bg-surface-2 px-[6px] py-[2px] text-[10.5px] font-semibold text-dim"
    >
      <History size={10} strokeWidth={2.5} />
      Backtest replay
    </span>
  );
}
