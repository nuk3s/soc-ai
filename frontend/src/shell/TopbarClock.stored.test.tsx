// Round 4, C3: this browser keeps the choice of the second clock in
// localStorage under one key. A bad stored value reads as "Off", storage that
// throws breaks nothing, and a second tab follows a change.
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  SECOND_CLOCK_KEY,
  SECOND_CLOCK_OFF,
  getSecondClock,
  parseSecondClock,
  reloadSecondClock,
  setSecondClock,
} from '../lib/clock';
import { TopbarClock } from './TopbarClock';

const TOKYO = JSON.stringify({ version: 1, mode: 'zone', zone: 'Asia/Tokyo' });

const second = () => screen.queryByTestId('topbar-clock-second');

const pickTokyo = () => {
  fireEvent.click(screen.getByTestId('topbar-clock-button'));
  const p = screen.getByRole('dialog', { name: 'Second clock' });
  fireEvent.click(within(p).getByRole('radio', { name: 'Another zone' }));
  fireEvent.change(within(p).getByRole('textbox', { name: 'Filter the zones' }), { target: { value: 'tokyo' } });
  fireEvent.click(within(p).getByRole('button', { name: 'Asia/Tokyo' }));
};

/** Another tab wrote the key: this tab gets the `storage` event. */
const otherTabWrites = (key: string | null, value: string | null) =>
  act(() => {
    if (key && value !== null) localStorage.setItem(key, value);
    if (key && value === null) localStorage.removeItem(key);
    window.dispatchEvent(new StorageEvent('storage', { key, newValue: value }));
  });

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-11-19T14:32:10Z'));
  localStorage.clear();
  setSecondClock(SECOND_CLOCK_OFF);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  localStorage.clear();
});

describe('the stored choice of the second clock', () => {
  it('keeps the picked zone under one key and reads it after a reload', async () => {
    const { unmount } = render(<TopbarClock />);
    pickTokyo();
    expect(JSON.parse(localStorage.getItem(SECOND_CLOCK_KEY)!)).toEqual({
      version: 1,
      mode: 'zone',
      zone: 'Asia/Tokyo',
    });
    unmount();
    // A reload loads the module again, and it reads the stored choice.
    vi.resetModules();
    const fresh = await import('../lib/clock');
    expect(fresh.getSecondClock()).toEqual({ mode: 'zone', zone: 'Asia/Tokyo' });
    // The clock of a new page reads it too.
    reloadSecondClock();
    render(<TopbarClock />);
    expect(second()!.getAttribute('title')).toMatch(/^2026-11-19 23:32 \S+, Asia\/Tokyo$/);
  });

  it('removes the key for "Off"', () => {
    localStorage.setItem(SECOND_CLOCK_KEY, TOKYO);
    reloadSecondClock();
    render(<TopbarClock />);
    expect(second()).not.toBeNull();
    fireEvent.click(screen.getByTestId('topbar-clock-button'));
    fireEvent.click(screen.getByRole('radio', { name: 'Off' }));
    expect(localStorage.getItem(SECOND_CLOCK_KEY)).toBeNull();
    expect(second()).toBeNull();
  });

  it('reads a bad stored value as "Off"', () => {
    for (const raw of [
      '{not json',
      'null',
      '42',
      '[]',
      '{"mode":"moon"}',
      '{"mode":"zone"}',
      '{"mode":"zone","zone":"Mars/Olympus"}',
      '{"mode":"zone","zone":7}',
    ]) {
      expect(parseSecondClock(raw)).toEqual(SECOND_CLOCK_OFF);
    }
    expect(parseSecondClock(null)).toEqual(SECOND_CLOCK_OFF);
    // Negative control: a good value reads as itself.
    expect(parseSecondClock('{"mode":"browser"}')).toEqual({ mode: 'browser' });
    expect(parseSecondClock(TOKYO)).toEqual({ mode: 'zone', zone: 'Asia/Tokyo' });

    localStorage.setItem(SECOND_CLOCK_KEY, '{"mode":"zone","zone":"Mars/Olympus"}');
    reloadSecondClock();
    render(<TopbarClock />);
    expect(second()).toBeNull();
    expect(screen.getByTestId('topbar-clock-utc').textContent).toBe('14:32 UTC');
  });

  it('keeps the clocks and the choice for this tab when storage throws', () => {
    const refuse = () => {
      throw new DOMException('The storage is off.', 'SecurityError');
    };
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(refuse);
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(refuse);
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(refuse);
    reloadSecondClock();
    expect(getSecondClock()).toEqual(SECOND_CLOCK_OFF);
    render(<TopbarClock />);
    expect(screen.getByTestId('topbar-clock-utc').textContent).toBe('14:32 UTC');
    pickTokyo();
    expect(second()!.getAttribute('title')).toMatch(/, Asia\/Tokyo$/);
    fireEvent.click(screen.getByTestId('topbar-clock-button'));
    fireEvent.click(screen.getByRole('radio', { name: 'Off' }));
    expect(second()).toBeNull();
  });
});

describe('a second tab of the console', () => {
  it('follows a change of the key in another tab', () => {
    render(<TopbarClock />);
    expect(second()).toBeNull();
    otherTabWrites(SECOND_CLOCK_KEY, TOKYO);
    expect(second()!.getAttribute('title')).toMatch(/, Asia\/Tokyo$/);
    otherTabWrites(SECOND_CLOCK_KEY, JSON.stringify({ version: 1, mode: 'browser' }));
    expect(second()!.getAttribute('title')).not.toMatch(/, Asia\/Tokyo$/);
    otherTabWrites(SECOND_CLOCK_KEY, null);
    expect(second()).toBeNull();
  });

  it('follows a clear of the whole storage', () => {
    localStorage.setItem(SECOND_CLOCK_KEY, TOKYO);
    reloadSecondClock();
    render(<TopbarClock />);
    expect(second()).not.toBeNull();
    act(() => {
      localStorage.clear();
      window.dispatchEvent(new StorageEvent('storage', { key: null }));
    });
    expect(second()).toBeNull();
  });

  it('ignores a change of another key', () => {
    // Negative control: the event of another key reads nothing.
    render(<TopbarClock />);
    localStorage.setItem(SECOND_CLOCK_KEY, TOKYO);
    otherTabWrites('soc-ai.dashboard.layout', '{}');
    expect(second()).toBeNull();
  });
});
