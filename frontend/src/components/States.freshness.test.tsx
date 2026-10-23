// The "updated" marker beside a list title. Its tooltip read a bare clock time
// with no date and no zone ("Last updated 14:23:05"), and past an hour the
// label counted hours where the lists below it counted days.
import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { absoluteTime } from '../lib/timeRange';
import { Freshness } from './States';

afterEach(() => {
  vi.useRealTimers();
});

describe('Freshness', () => {
  it('states the absolute time with its zone in the tooltip', () => {
    const at = Date.now() - 30_000;
    render(<Freshness at={at} />);
    const marker = screen.getByText(/^updated /);
    expect(marker.getAttribute('title')).toBe(`Last updated ${absoluteTime(at)}`);
    expect(marker.getAttribute('title')).toMatch(/\d{4}-\d{2}-\d{2} \d{2}:\d{2} \S+$/);
  });

  it('counts seconds under a minute and uses the shared scale after', () => {
    // The label rounds to the second. Hold the clock, so a slow render on a
    // loaded runner cannot read "31s ago".
    vi.useFakeTimers({ toFake: ['Date'] });
    const { rerender } = render(<Freshness at={Date.now() - 30_000} />);
    expect(screen.getByText('updated 30s ago')).toBeTruthy();
    rerender(<Freshness at={Date.now() - 26 * 3_600_000} />);
    // The shared formatter reads days from 24 hours on.
    expect(screen.getByText('updated 1d ago')).toBeTruthy();
    // Negative control: the old scale said "26h ago".
    expect(screen.queryByText('updated 26h ago')).toBeNull();
  });

  it('renders nothing before the first load', () => {
    const { container } = render(<Freshness at={null} />);
    expect(container.textContent).toBe('');
  });
});
