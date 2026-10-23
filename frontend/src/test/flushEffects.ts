import { act } from '@testing-library/react';
import { createRoot } from 'react-dom/client';

/** Run the effects that React still owes for its last render, now.
 *
 * A render that a resolved promise starts runs outside act. React runs the
 * effects of that render in a later task. On a loaded runner a test can see the
 * new DOM before that task runs, so a timer that an effect starts does not exist
 * yet. A test that then moves a fake clock moves it past nothing.
 *
 * React runs every pending effect before it renders anything else. This renders
 * an empty root inside act, so the pending effects run before it returns. Call
 * it before a fake clock moves past a timer that an effect of an async render
 * starts. */
export function flushEffects(): void {
  const root = createRoot(document.createElement('div'));
  act(() => root.render(null));
  act(() => root.unmount());
}
