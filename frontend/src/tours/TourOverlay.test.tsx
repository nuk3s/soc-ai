// The tour engine: anchors, skipped steps, keys, focus and the card.
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { placeCard, spotlightBox } from './anchors';
import { TourOverlay } from './TourOverlay';
import type { Tour } from './types';

const TOUR: Tour = {
  id: 'test-tour',
  version: 1,
  name: 'Test',
  routes: ['/test'],
  steps: [
    { anchor: 'one', title: 'First part', body: 'The first part does one thing.' },
    { anchor: 'two', title: 'Second part', body: 'The second part does another thing.' },
    { anchor: 'three', title: 'Third part', body: 'The third part ends the tour.' },
  ],
};

function Page({ anchors = ['one', 'two', 'three'] }: { anchors?: string[] }) {
  return (
    <div>
      <button type="button" data-testid="opener">
        Opener
      </button>
      {anchors.map((a) => (
        <div key={a} data-tour={a}>
          {a}
        </div>
      ))}
    </div>
  );
}

function mount(opts: { anchors?: string[]; tour?: Tour; focusOpener?: boolean } = {}) {
  const onEnd = vi.fn();
  const page = render(<Page anchors={opts.anchors} />);
  if (opts.focusOpener) screen.getByTestId('opener').focus();
  const overlay = render(<TourOverlay tour={opts.tour ?? TOUR} onEnd={onEnd} />);
  return { onEnd, page, overlay };
}

const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 5)); });
const card = () => screen.getByRole('dialog');
const key = (k: string, opts: KeyboardEventInit = {}) =>
  act(() => {
    fireEvent.keyDown(document.activeElement ?? document.body, { key: k, ...opts });
  });

afterEach(() => {
  cleanup();
});

describe('TourOverlay', () => {
  it('shows the step of the first anchor as a dialog that leaves the page readable', async () => {
    mount();
    await flush();
    const dialog = card();
    expect(dialog).toHaveAttribute('aria-modal', 'false');
    expect(dialog).toHaveAccessibleName('First part');
    expect(dialog).toHaveAccessibleDescription('The first part does one thing.');
    expect(screen.getByTestId('tour-progress')).toHaveTextContent('1 of 3');
    expect(screen.getByTestId('tour-announce')).toHaveTextContent('Step 1 of 3. First part.');
    // The page under the overlay takes no click during a step.
    expect(screen.getByTestId('tour-blocker')).toBeInTheDocument();
  });

  it('skips a step whose anchor is not on the page, and counts only the steps that show', async () => {
    const { onEnd } = mount({ anchors: ['one', 'three'] });
    await flush();
    expect(screen.getByTestId('tour-progress')).toHaveTextContent('1 of 2');
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await flush();
    expect(card()).toHaveAccessibleName('Third part');
    expect(screen.getByTestId('tour-progress')).toHaveTextContent('2 of 2');
    // The last step shown offers Done and Turn off tours.
    expect(screen.getByRole('button', { name: 'Turn off tours' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Done' }));
    expect(onEnd).toHaveBeenCalledWith('done');
  });

  it('starts at the first anchor that is present', async () => {
    mount({ anchors: ['two', 'three'] });
    await flush();
    expect(card()).toHaveAccessibleName('Second part');
    expect(screen.getByRole('button', { name: 'Back' })).toHaveAttribute('aria-disabled', 'true');
  });

  it('does not start when no anchor is on the page', async () => {
    const { onEnd } = mount({ anchors: [] });
    await flush();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(onEnd).toHaveBeenCalledWith('empty');
    expect(onEnd).toHaveBeenCalledTimes(1);
  });

  it('treats a hidden anchor as absent', async () => {
    render(
      <div>
        <div data-tour="one" style={{ display: 'none' }}>
          one
        </div>
        <div data-tour="two">two</div>
      </div>,
    );
    render(<TourOverlay tour={TOUR} onEnd={vi.fn()} />);
    await flush();
    expect(card()).toHaveAccessibleName('Second part');
  });

  it('treats an anchor with no area as absent where the browser lays the page out', async () => {
    const box = (w: number, h: number) => ({ width: w, height: h, top: 0, left: 0, right: w, bottom: h, x: 0, y: 0, toJSON: () => ({}) });
    const root = vi.spyOn(document.documentElement, 'getBoundingClientRect').mockReturnValue(box(1280, 800) as DOMRect);
    try {
      render(
        <div>
          <div data-tour="one" ref={(el) => el && vi.spyOn(el, 'getBoundingClientRect').mockReturnValue(box(400, 0) as DOMRect)} />
          <div data-tour="two" ref={(el) => el && vi.spyOn(el, 'getBoundingClientRect').mockReturnValue(box(400, 30) as DOMRect)}>
            two
          </div>
        </div>,
      );
      render(<TourOverlay tour={TOUR} onEnd={vi.fn()} />);
      await flush();
      expect(card()).toHaveAccessibleName('Second part');
      expect(screen.getByTestId('tour-progress')).toHaveTextContent('1 of 1');
    } finally {
      root.mockRestore();
    }
  });

  it('scrolls a step into view and returns the page to where it stood when the tour ends', async () => {
    const box = (top: number) => ({ width: 200, height: 40, top, left: 0, right: 200, bottom: top + 40, x: 0, y: top, toJSON: () => ({}) });
    const intoView = vi.fn();
    render(
      <div>
        <div data-tour="one">one</div>
        <div
          data-tour="two"
          ref={(el) => {
            if (!el) return;
            vi.spyOn(el, 'getBoundingClientRect').mockReturnValue(box(5000) as DOMRect);
            el.scrollIntoView = intoView;
          }}
        >
          two
        </div>
      </div>,
    );
    const scrollTo = vi.spyOn(window, 'scrollTo').mockImplementation(() => {});
    const onEnd = vi.fn();
    try {
      render(<TourOverlay tour={TOUR} onEnd={onEnd} />);
      await flush();
      key('ArrowRight');
      await flush();
      expect(intoView).toHaveBeenCalledTimes(1);
      expect(scrollTo).not.toHaveBeenCalled();
      key('Escape');
      expect(scrollTo).toHaveBeenCalledWith({ top: 0, behavior: 'auto' });
      expect(onEnd).toHaveBeenCalledWith('closed');
    } finally {
      scrollTo.mockRestore();
    }
  });

  it('moves with the arrow keys and closes on Escape', async () => {
    const { onEnd } = mount();
    await flush();
    key('ArrowRight');
    expect(card()).toHaveAccessibleName('Second part');
    key('ArrowRight');
    expect(card()).toHaveAccessibleName('Third part');
    key('ArrowLeft');
    expect(card()).toHaveAccessibleName('Second part');
    expect(onEnd).not.toHaveBeenCalled();
    key('Escape');
    expect(onEnd).toHaveBeenCalledWith('closed');
  });

  it('keeps page keys away from the page while the tour runs', async () => {
    mount();
    await flush();
    const pageKey = vi.fn();
    window.addEventListener('keydown', pageKey);
    try {
      act(() => {
        fireEvent.keyDown(screen.getByTestId('opener'), { key: 'j' });
      });
      expect(pageKey).not.toHaveBeenCalled();
    } finally {
      window.removeEventListener('keydown', pageKey);
    }
  });

  it('moves the focus to the card on open and back to the opener on close', async () => {
    const { overlay } = mount({ focusOpener: true });
    await flush();
    expect(card()).toHaveFocus();
    overlay.unmount();
    expect(screen.getByTestId('opener')).toHaveFocus();
  });

  it('keeps Tab inside the card', async () => {
    mount();
    await flush();
    const buttons = Array.from(card().querySelectorAll('button'));
    const first = buttons[0];
    const last = buttons[buttons.length - 1];
    last.focus();
    key('Tab');
    expect(first).toHaveFocus();
    key('Tab', { shiftKey: true });
    expect(last).toHaveFocus();
    // Tab from the page goes into the card.
    screen.getByTestId('opener').focus();
    key('Tab');
    expect(first).toHaveFocus();
  });

  it('closes from the close button', async () => {
    const { onEnd } = mount();
    await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Close the tour' }));
    expect(onEnd).toHaveBeenCalledWith('closed');
  });

  it('offers Turn off tours in the Skip flow', async () => {
    const { onEnd } = mount();
    await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Skip' }));
    expect(card()).toHaveAccessibleName('Tours');
    expect(screen.getByTestId('tour-announce')).toHaveTextContent('Tour skipped.');
    // The arrows do nothing on the Skip panel.
    key('ArrowLeft');
    expect(card()).toHaveAccessibleName('Tours');
    fireEvent.click(screen.getByRole('button', { name: 'Turn off tours' }));
    expect(onEnd).toHaveBeenCalledWith('off');
  });

  it('ends as skipped when the operator keeps the tours on, or presses Escape on the Skip panel', async () => {
    const first = mount();
    await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Skip' }));
    fireEvent.click(screen.getByRole('button', { name: 'Keep tours on' }));
    expect(first.onEnd).toHaveBeenCalledWith('skipped');
    cleanup();

    const second = mount();
    await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Skip' }));
    key('Escape');
    expect(second.onEnd).toHaveBeenCalledWith('skipped');
  });

  it('ends once, however many ways the operator closes it', async () => {
    const { onEnd } = mount();
    await flush();
    key('Escape');
    key('Escape');
    expect(onEnd).toHaveBeenCalledTimes(1);
  });

  it('lets the spotlit element take a click on a Try it step', async () => {
    const tryIt: Tour = { ...TOUR, steps: [{ ...TOUR.steps[0], tryIt: true }] };
    mount({ tour: tryIt });
    await flush();
    // happy-dom lays nothing out, so the anchor box is 0 x 0. The step still
    // draws its four blockers around the hole, and no full blocker.
    expect(screen.queryByTestId('tour-blocker')).toBeNull();
    expect(screen.getByText('The highlighted control works during the tour. Try it.')).toBeInTheDocument();
  });
});

describe('placeCard', () => {
  const card = { width: 320, height: 200 };
  const views = [
    { width: 1280, height: 800 },
    { width: 1600, height: 1000 },
  ];

  it('puts the card under an anchor with room below', () => {
    const place = placeCard({ top: 60, left: 400, width: 200, height: 40 }, card, views[0]);
    expect(place.side).toBe('bottom');
    expect(place.top).toBe(60 + 40 + 12);
  });

  it('moves the card above an anchor at the bottom of the window', () => {
    const place = placeCard({ top: 700, left: 400, width: 200, height: 40 }, card, views[0]);
    expect(place.side).toBe('top');
  });

  it('honours the placement of the step when it fits', () => {
    const place = placeCard({ top: 60, left: 10, width: 200, height: 600 }, card, views[0], 'right');
    expect(place.side).toBe('right');
    expect(place.left).toBe(10 + 200 + 12);
  });

  it('never leaves the viewport, for anchors at every edge and corner', () => {
    for (const view of views) {
      const anchors = [
        { top: 0, left: 0, width: 30, height: 30 },
        { top: 0, left: view.width - 30, width: 30, height: 30 },
        { top: view.height - 30, left: 0, width: 30, height: 30 },
        { top: view.height - 30, left: view.width - 30, width: 30, height: 30 },
        { top: 52, left: 212, width: view.width - 212, height: view.height - 52 },
        { top: -400, left: 300, width: 600, height: 2000 },
      ];
      for (const a of anchors) {
        for (const placement of ['auto', 'top', 'bottom', 'left', 'right'] as const) {
          const p = placeCard(a, card, view, placement);
          expect(p.left).toBeGreaterThanOrEqual(12);
          expect(p.top).toBeGreaterThanOrEqual(12);
          expect(p.left + card.width).toBeLessThanOrEqual(view.width - 12);
          expect(p.top + card.height).toBeLessThanOrEqual(view.height - 12);
        }
      }
    }
  });

  it('takes the corner that covers the least of a large anchor', () => {
    const view = views[0];
    // The anchor leaves no side with room. Its right edge is at 1010, so the
    // right corners cover the least of it.
    const place = placeCard({ top: 10, left: 10, width: 1000, height: 780 }, card, view);
    expect(place.side).toBe('over');
    expect(place.left).toBe(view.width - card.width - 12);
    // An anchor on the right of the window sends the card to the left.
    const left = placeCard({ top: 10, left: 270, width: 1000, height: 780 }, card, view);
    expect(left.left).toBe(12);
  });

  it('sits over the corner when the anchor fills the window', () => {
    const view = views[0];
    const place = placeCard({ top: 10, left: 10, width: view.width - 20, height: view.height - 20 }, card, view);
    expect(place.side).toBe('over');
  });

  it('cuts the spotlight to the viewport', () => {
    const box = spotlightBox({ top: -100, left: 100, width: 200, height: 2000 }, views[0]);
    expect(box.top).toBeGreaterThanOrEqual(0);
    expect(box.top + box.height).toBeLessThanOrEqual(800);
  });
});
