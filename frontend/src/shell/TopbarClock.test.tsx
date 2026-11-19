// Round 4, C1: the top bar states the time now in UTC to the minute. Every
// absolute time of the console reads UTC, and the bar held no clock.
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SECOND_CLOCK_OFF, browserTimeZone, setSecondClock, zoneClock } from '../lib/clock';
import { TopbarClock, ZONE_HINT } from './TopbarClock';

const AT = new Date('2026-11-19T14:32:10Z');

const advance = (ms: number) =>
  act(() => {
    vi.advanceTimersByTime(ms);
  });

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(AT);
  setSecondClock(SECOND_CLOCK_OFF);
});

afterEach(() => {
  vi.useRealTimers();
});

describe('TopbarClock: the UTC clock', () => {
  it('states the minute in UTC and the full date and time in the tooltip', () => {
    render(<TopbarClock />);
    const utc = screen.getByTestId('topbar-clock-utc');
    expect(utc.tagName).toBe('TIME');
    expect(utc.textContent).toBe('14:32 UTC');
    expect(utc.getAttribute('title')).toBe('2026-11-19 14:32 UTC');
    expect(utc.getAttribute('dateTime')).toBe('2026-11-19T14:32Z');
  });

  it('ticks on the minute', () => {
    render(<TopbarClock />);
    // 49.999 s after 14:32:10 the minute has not turned.
    advance(49_999);
    expect(screen.getByTestId('topbar-clock-utc').textContent).toBe('14:32 UTC');
    advance(1);
    expect(screen.getByTestId('topbar-clock-utc').textContent).toBe('14:33 UTC');
    advance(60_000);
    expect(screen.getByTestId('topbar-clock-utc').textContent).toBe('14:34 UTC');
    expect(screen.getByTestId('topbar-clock-utc').getAttribute('title')).toBe('2026-11-19 14:34 UTC');
  });

  it('turns the date at midnight UTC', () => {
    vi.setSystemTime(new Date('2026-11-19T23:59:30Z'));
    render(<TopbarClock />);
    advance(30_000);
    expect(screen.getByTestId('topbar-clock-utc').textContent).toBe('00:00 UTC');
    expect(screen.getByTestId('topbar-clock-utc').getAttribute('title')).toBe('2026-11-20 00:00 UTC');
  });

  it('is in no live region, so a screen reader hears no tick', () => {
    render(<TopbarClock />);
    const clock = screen.getByTestId('topbar-clock');
    expect(
      clock.closest('[aria-live],[role="status"],[role="log"],[role="timer"],[role="alert"],[role="marquee"]'),
    ).toBeNull();
    expect(clock.querySelector('[aria-live]')).toBeNull();
  });

  it('reads the time again when a hidden tab shows', () => {
    // Negative control: a tab in the background gets slow timers. The clock
    // must not wait for the next tick to state the time.
    let hidden = false;
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => hidden });
    render(<TopbarClock />);
    hidden = true;
    vi.setSystemTime(new Date('2026-11-19T15:07:40Z'));
    expect(screen.getByTestId('topbar-clock-utc').textContent).toBe('14:32 UTC');
    hidden = false;
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });
    expect(screen.getByTestId('topbar-clock-utc').textContent).toBe('15:07 UTC');
  });
});

const second = () => screen.queryByTestId('topbar-clock-second');
const clockButton = () => screen.getByTestId('topbar-clock-button');
const panel = () => screen.getByRole('dialog', { name: 'Second clock' });
const openPanel = () => {
  fireEvent.click(clockButton());
  return panel();
};
/** Pick a zone in the panel: check "Another zone", filter, press the zone. */
const pickZone = (filter: string, zone: string) => {
  const p = openPanel();
  fireEvent.click(within(p).getByRole('radio', { name: 'Another zone' }));
  fireEvent.change(within(p).getByRole('textbox', { name: 'Filter the zones' }), { target: { value: filter } });
  fireEvent.click(within(p).getByRole('button', { name: zone }));
};

// Round 4, C2: the analyst can add a second clock for a local time.
describe('TopbarClock: the second clock', () => {
  it('shows the UTC clock alone while the second clock is off', () => {
    // Negative control: "Off" is the default, and the bar states UTC only.
    render(<TopbarClock />);
    expect(second()).toBeNull();
    expect(clockButton().textContent).toBe('14:32 UTC');
  });

  it('opens a panel with the heading and three choices, and the focus on the checked one', () => {
    render(<TopbarClock />);
    expect(clockButton()).toHaveAttribute('aria-haspopup', 'dialog');
    expect(clockButton()).toHaveAttribute('aria-expanded', 'false');
    const p = openPanel();
    expect(clockButton()).toHaveAttribute('aria-expanded', 'true');
    expect(within(p).getByText('Second clock')).toBeTruthy();
    const radios = within(p).getAllByRole('radio');
    expect(radios.map((r) => r.closest('label')?.textContent)).toEqual([
      'Off',
      `Local time of this browser${browserTimeZone()}`,
      'Another zone',
    ]);
    expect(within(p).getByRole('radio', { name: 'Off' })).toBeChecked();
    expect(document.activeElement).toBe(within(p).getByRole('radio', { name: 'Off' }));
    // Round 4, C4: the hint says what a picked zone does.
    expect(within(p).getByRole('radio', { name: 'Another zone' })).toHaveAccessibleDescription(ZONE_HINT);
  });

  it('states both clocks, UTC first, when the analyst picks a zone', () => {
    render(<TopbarClock />);
    pickZone('chicago', 'America/Chicago');
    expect(screen.queryByRole('dialog', { name: 'Second clock' })).toBeNull();
    expect(document.activeElement).toBe(clockButton());
    const utc = screen.getByTestId('topbar-clock-utc');
    const local = second()!;
    expect(local.tagName).toBe('TIME');
    expect(local.textContent).toBe('08:32 CST');
    expect(local.getAttribute('title')).toBe('2026-11-19 08:32 CST, America/Chicago');
    expect(utc.compareDocumentPosition(local) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    // Both clocks tick on the minute.
    advance(50_000);
    expect(utc.textContent).toBe('14:33 UTC');
    expect(second()!.textContent).toBe('08:33 CST');
  });

  it('states the weekday when the date of the zone turns away from the UTC date', () => {
    vi.setSystemTime(new Date('2026-11-19T05:59:30Z'));
    render(<TopbarClock />);
    pickZone('chicago', 'America/Chicago');
    // 05:59 UTC on Thursday is 23:59 on Wednesday in Chicago.
    expect(second()!.textContent).toBe('Wed 23:59 CST');
    advance(30_000);
    // 06:00 UTC: the dates agree again, and the weekday goes.
    expect(second()!.textContent).toBe('00:00 CST');
    expect(screen.getByTestId('topbar-clock-utc').textContent).toBe('06:00 UTC');
  });

  it('states the zone of this browser for the local time of this browser', () => {
    render(<TopbarClock />);
    fireEvent.click(within(openPanel()).getByRole('radio', { name: /^Local time of this browser/ }));
    const want = zoneClock(new Date(), browserTimeZone());
    expect(second()!.textContent).toBe(want.text);
    expect(second()!.getAttribute('title')).toBe(want.title);
    // "Off" takes the second clock away again.
    fireEvent.click(within(panel()).getByRole('radio', { name: 'Off' }));
    expect(second()).toBeNull();
  });

  it('marks the picked zone and states the reading of the second clock in the panel', () => {
    render(<TopbarClock />);
    pickZone('tokyo', 'Asia/Tokyo');
    const p = openPanel();
    expect(within(p).getByRole('radio', { name: /^Another zone/ })).toBeChecked();
    expect(within(p).getByRole('button', { name: 'Asia/Tokyo' })).toHaveAttribute('aria-pressed', 'true');
    expect(within(p).getByTestId('clock-menu-second').textContent).toBe(`${second()!.textContent} · Asia/Tokyo`);
  });

  it('filters the zones by text and states when no zone holds it', () => {
    render(<TopbarClock />);
    const p = openPanel();
    fireEvent.click(within(p).getByRole('radio', { name: 'Another zone' }));
    const box = within(p).getByRole('textbox', { name: 'Filter the zones' });
    fireEvent.change(box, { target: { value: 'new york' } });
    const list = within(p).getByTestId('clock-zone-list');
    expect(within(list).getAllByRole('button').map((b) => b.textContent)).toEqual(['America/New_York']);
    fireEvent.change(box, { target: { value: 'no such zone' } });
    expect(within(list).queryAllByRole('button')).toHaveLength(0);
    expect(list.textContent).toBe('No zone holds this text.');
  });

  it('keeps the choice until a zone is picked', () => {
    // Negative control: "Another zone" alone changes no clock.
    render(<TopbarClock />);
    fireEvent.click(within(openPanel()).getByRole('radio', { name: 'Another zone' }));
    expect(second()).toBeNull();
  });

  it('moves from the filter to the zones with the arrow keys and picks with Enter', () => {
    render(<TopbarClock />);
    const p = openPanel();
    fireEvent.click(within(p).getByRole('radio', { name: 'Another zone' }));
    const box = within(p).getByRole('textbox', { name: 'Filter the zones' });
    fireEvent.change(box, { target: { value: 'america/' } });
    fireEvent.keyDown(box, { key: 'ArrowDown' });
    const zones = within(within(p).getByTestId('clock-zone-list')).getAllByRole('button');
    expect(document.activeElement).toBe(zones[0]);
    fireEvent.keyDown(zones[0], { key: 'ArrowDown' });
    expect(document.activeElement).toBe(zones[1]);
    fireEvent.keyDown(zones[1], { key: 'ArrowUp' });
    fireEvent.keyDown(zones[0], { key: 'ArrowUp' });
    expect(document.activeElement).toBe(box);
    fireEvent.change(box, { target: { value: 'tokyo' } });
    fireEvent.keyDown(box, { key: 'Enter' });
    expect(screen.queryByRole('dialog', { name: 'Second clock' })).toBeNull();
    expect(second()!.getAttribute('title')).toMatch(/, Asia\/Tokyo$/);
  });

  it('closes on Escape and gives the focus back to the clocks', () => {
    render(<TopbarClock />);
    openPanel();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('dialog', { name: 'Second clock' })).toBeNull();
    expect(document.activeElement).toBe(clockButton());
    expect(clockButton()).toHaveAttribute('aria-expanded', 'false');
  });

  it('closes on a click on the page and stays open on a click inside it', () => {
    const { container } = render(
      <>
        <TopbarClock />
        <button type="button">Page button</button>
      </>,
    );
    const p = openPanel();
    fireEvent.mouseDown(p);
    expect(screen.getByRole('dialog', { name: 'Second clock' })).toBeTruthy();
    fireEvent.mouseDown(within(container).getByRole('button', { name: 'Page button' }));
    expect(screen.queryByRole('dialog', { name: 'Second clock' })).toBeNull();
  });

  it('closes when the focus leaves it', () => {
    render(
      <>
        <TopbarClock />
        <button type="button">Next</button>
      </>,
    );
    const p = openPanel();
    const next = screen.getByRole('button', { name: 'Next' });
    fireEvent.blur(within(p).getByRole('radio', { name: 'Off' }), { relatedTarget: next });
    expect(screen.queryByRole('dialog', { name: 'Second clock' })).toBeNull();
  });
});
