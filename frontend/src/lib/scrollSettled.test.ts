// R1-D12: the shadow-hit link landed on the leads block. The page scrolled
// to the hits block at once, and the leads above it rendered later and
// pushed it down by their own height.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { scrollIntoViewSettled } from './scrollSettled';

let top = 0;
let el: HTMLElement;

beforeEach(() => {
  vi.useFakeTimers();
  el = document.createElement('div');
  el.id = 'analytic-hits';
  document.body.appendChild(el);
  top = 1015;
  el.getBoundingClientRect = () => ({ top }) as DOMRect;
  el.scrollIntoView = vi.fn(() => {
    top = 0;
  });
});

afterEach(() => {
  vi.useRealTimers();
  el.remove();
});

describe('scrollIntoViewSettled', () => {
  it('scrolls again when a block above renders and moves the target', () => {
    const stop = scrollIntoViewSettled('analytic-hits');
    vi.advanceTimersByTime(0);
    expect(el.scrollIntoView).toHaveBeenCalledTimes(1);
    // The leads render above the block.
    top = 640;
    vi.advanceTimersByTime(150);
    expect(el.scrollIntoView).toHaveBeenCalledTimes(2);
    expect(top).toBe(0);
    // A target that stays put is not scrolled again.
    vi.advanceTimersByTime(500);
    expect(el.scrollIntoView).toHaveBeenCalledTimes(2);
    stop();
  });

  it('waits for a target that is not on the page yet', () => {
    el.remove();
    scrollIntoViewSettled('analytic-hits');
    vi.advanceTimersByTime(200);
    expect(el.scrollIntoView).not.toHaveBeenCalled();
    document.body.appendChild(el);
    vi.advanceTimersByTime(150);
    expect(el.scrollIntoView).toHaveBeenCalledTimes(1);
  });

  it('stops at the first input of the analyst', () => {
    scrollIntoViewSettled('analytic-hits');
    vi.advanceTimersByTime(0);
    window.dispatchEvent(new Event('wheel'));
    top = 640;
    vi.advanceTimersByTime(500);
    expect(el.scrollIntoView).toHaveBeenCalledTimes(1);
  });

  it('stops when the settle time ends', () => {
    scrollIntoViewSettled('analytic-hits', 300);
    vi.advanceTimersByTime(0);
    vi.advanceTimersByTime(400);
    top = 640;
    vi.advanceTimersByTime(500);
    expect(el.scrollIntoView).toHaveBeenCalledTimes(1);
  });
});
