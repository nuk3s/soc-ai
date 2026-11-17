import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { HoverTip } from './HoverTip';

/** A graphic at a fixed place in the window. */
function graphic(left: number, top: number): HTMLElement {
  const el = document.createElement('div');
  el.getBoundingClientRect = () => ({ left, top, right: left, bottom: top, width: 0, height: 0, x: left, y: top, toJSON: () => ({}) });
  return el;
}

function windowSize(width: number, height: number) {
  vi.spyOn(document.documentElement, 'clientWidth', 'get').mockReturnValue(width);
  vi.spyOn(document.documentElement, 'clientHeight', 'get').mockReturnValue(height);
}

function tipHeight(height: number) {
  vi.spyOn(HTMLElement.prototype, 'offsetHeight', 'get').mockReturnValue(height);
}

afterEach(() => vi.restoreAllMocks());

describe('HoverTip', () => {
  it('draws on the document body, so a panel that clips does not cut it', () => {
    windowSize(1200, 800);
    const { container } = render(
      <div style={{ overflow: 'hidden' }}>
        <HoverTip testId="tip" container={graphic(100, 100)} x={20} y={30} width={280} gap={14}>
          24 alerts
        </HoverTip>
      </div>,
    );
    const tip = screen.getByTestId('tip');
    expect(container.contains(tip)).toBe(false);
    expect(tip.parentElement).toBe(document.body);
    expect(tip).toHaveTextContent('24 alerts');
    expect(tip).toHaveClass('fixed');
    expect(tip).toHaveStyle({ left: '120px', top: '144px', visibility: 'visible' });
  });

  it('opens below its mark when the room is sufficient', () => {
    windowSize(1200, 800);
    tipHeight(200);
    render(
      <HoverTip testId="tip" container={graphic(0, 400)} x={50} y={100} width={290} gap={6} rise={30}>
        text
      </HoverTip>,
    );
    expect(screen.getByTestId('tip')).toHaveStyle({ top: '506px' });
  });

  it('opens above its mark when the room below is too small', () => {
    windowSize(1200, 800);
    tipHeight(200);
    render(
      <HoverTip testId="tip" container={graphic(0, 600)} x={50} y={100} width={290} gap={6} rise={30}>
        text
      </HoverTip>,
    );
    // The mark ends at 700. The tooltip clears the mark of 30 and the gap of 6.
    expect(screen.getByTestId('tip')).toHaveStyle({ top: '464px' });
  });

  it('stays in the window at the right edge and at the left edge', () => {
    windowSize(1000, 800);
    const { unmount } = render(
      <HoverTip testId="tip" container={graphic(0, 0)} x={900} y={10} width={290} gap={6}>
        text
      </HoverTip>,
    );
    expect(screen.getByTestId('tip')).toHaveStyle({ left: '702px' });
    unmount();
    render(
      <HoverTip testId="tip" container={graphic(0, 0)} x={-100} y={10} width={290} gap={6}>
        text
      </HoverTip>,
    );
    expect(screen.getByTestId('tip')).toHaveStyle({ left: '8px' });
  });
});
