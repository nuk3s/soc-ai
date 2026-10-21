// ---------------------------------------------------------------------------
// Scroll a block into view, and keep it there while the page above it settles.
//
// The Needs-you link and the bell open /hunts#analytic-hits. The page scrolled
// to the hits block at once, and the leads block above it rendered later and
// pushed the hits block down by its own height. The link landed on the leads
// (R1-D12). This helper scrolls again each time the target moves, for a short
// settle time, and stops at the first input of the analyst.
// ---------------------------------------------------------------------------

/** The inputs that end the settle time. The scroll event is not one: the
 *  helper's own scroll fires it. */
const USER_INPUT = ['wheel', 'touchstart', 'keydown', 'mousedown'] as const;

/** Scroll the element with `id` into view now, and again each time it moves,
 *  for `settleMs`. A target that is not on the page yet is scrolled to when it
 *  arrives. Returns a function that stops the helper. */
export function scrollIntoViewSettled(id: string, settleMs = 2500, stepMs = 100): () => void {
  let stopped = false;
  let lastTop: number | null = null;
  let elapsed = 0;

  const tick = () => {
    if (stopped) return;
    const el = document.getElementById(id);
    if (el) {
      const top = el.getBoundingClientRect().top;
      if (lastTop === null || Math.abs(top - lastTop) > 2) {
        el.scrollIntoView();
        lastTop = el.getBoundingClientRect().top;
      }
    }
  };

  const first = window.setTimeout(tick, 0);
  const timer = window.setInterval(() => {
    elapsed += stepMs;
    tick();
    if (elapsed >= settleMs) stop();
  }, stepMs);

  function stop() {
    if (stopped) return;
    stopped = true;
    window.clearTimeout(first);
    window.clearInterval(timer);
    for (const type of USER_INPUT) window.removeEventListener(type, stop);
  }

  for (const type of USER_INPUT) window.addEventListener(type, stop, { passive: true });
  return stop;
}
