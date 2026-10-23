// An opt-in imitation of a loaded CI runner for React's scheduler.
//
// Off unless vitest runs in mode "loaded" (`npm run test:loaded`) or
// SOC_AI_LOADED_SCHEDULER=1 is set. It must load before React, so
// vite.config.ts lists it before setup.ts.
//
// Why: React's scheduler (Node path) runs renders and effects on setImmediate,
// and testing-library ends every wait on a setTimeout(0). On an idle box the
// immediate runs first, so a test that reads too early still passes. On a
// loaded runner the order flips, and React also yields between a render and
// its effects. The test then reads before the render or the effect, and fails
// once in a while on GitHub. This mode makes the loaded order the usual order:
//
// - setImmediate becomes a timer of SOC_AI_LOADED_DELAY_MS (default 3 ms), so
//   React's next task runs after a testing-library wait has ended.
// - performance.now moves SOC_AI_LOADED_STEP_MS (default 3 ms) on each read, so
//   the scheduler yields between tasks: a commit and its effects split in two.
//   React's own render loop keeps going, so a render stays whole and fast.
//
// A test that fails here and passes in `npm test` reads in that gap. Fix the
// test: wait for the text with findBy or waitFor, or call flushEffects() from
// ./flushEffects before a key press or a fake clock move. Do not fix it here.
// On 2026-10-22 two settings of this mode failed 41 tests in 18 files on a
// suite that passed. Two of those tests had failed a loaded run that day.
import { createRequire } from 'node:module';

if (import.meta.env.MODE === 'loaded' || process.env.SOC_AI_LOADED_SCHEDULER === '1') {
  const realSetTimeout = globalThis.setTimeout;
  const realClearTimeout = globalThis.clearTimeout;
  const delay = Number(process.env.SOC_AI_LOADED_DELAY_MS ?? '3');
  const step = Number(process.env.SOC_AI_LOADED_STEP_MS ?? '3');

  const later = (fn: (...args: unknown[]) => void, ...args: unknown[]) => realSetTimeout(fn, delay, ...args);
  (globalThis as unknown as { setImmediate: unknown }).setImmediate = later;
  (globalThis as unknown as { clearImmediate: unknown }).clearImmediate = (t: ReturnType<typeof setTimeout>) =>
    realClearTimeout(t);

  if (step > 0) {
    // React reads Scheduler.unstable_shouldYield once, when react-dom loads.
    // A render that yields after every fiber is slow and proves nothing more.
    const scheduler = createRequire(import.meta.url)('scheduler') as { unstable_shouldYield: () => boolean };
    scheduler.unstable_shouldYield = () => false;
    const realNow = performance.now.bind(performance);
    let skew = 0;
    performance.now = () => {
      skew += step;
      return realNow() + skew;
    };
  }
}
