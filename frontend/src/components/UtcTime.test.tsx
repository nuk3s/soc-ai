// Round 3, T3: a page shows an absolute time in UTC with the label, in the
// form of the investigation page. The tooltip states the local time with its
// zone. The host rows and the entity rows showed a local time with no zone.
import { act, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { SECOND_CLOCK_OFF, browserTimeZone, setSecondClock } from '../lib/clock';
import { absoluteTime, localTitle, timeTitle } from '../lib/timeRange';
import { RelTime } from './RelTime';
import { UtcTime } from './UtcTime';

describe('UtcTime', () => {
  it('states the time in UTC with the label and the local time in the tooltip', async () => {
    render(<UtcTime testId="t" iso="2026-10-02T12:10:28Z" />);
    const t = await screen.findByTestId('t');
    expect(t.tagName).toBe('TIME');
    expect(t.textContent).toBe('2026-10-02 12:10:28 UTC');
    expect(t.getAttribute('dateTime')).toBe('2026-10-02T12:10:28Z');
    expect(t.getAttribute('title')).toBe(localTitle('2026-10-02T12:10:28Z'));
    expect(t.getAttribute('title')).toMatch(/^Local time: 2026-10-02 \d{2}:\d{2} \S+$/);
  });

  it('reads an offset time as the same instant in UTC', async () => {
    render(<UtcTime testId="t" iso="2026-10-02T08:10:28-04:00" />);
    expect((await screen.findByTestId('t')).textContent).toBe('2026-10-02 12:10:28 UTC');
  });

  it('shows a dash and no tooltip for no time', async () => {
    // Negative control: no value reads as a time, and no tooltip names one.
    render(<UtcTime testId="t" iso={null} />);
    const t = await screen.findByTestId('t');
    expect(t.textContent).toBe('—');
    expect(t.getAttribute('title')).toBeNull();
    expect(t.getAttribute('dateTime')).toBeNull();
  });
});

// Round 3 part 2, P1: one component gives a relative time and one gives an
// absolute time. A relative time states both clocks in its tooltip.
describe('UtcTime span', () => {
  it('states a span in UTC and both ends in local time in the tooltip', async () => {
    render(<UtcTime testId="t" iso="2026-10-02T12:10:00Z" to="2026-10-02T13:40:00Z" seconds={false} />);
    const t = await screen.findByTestId('t');
    expect(t.textContent).toBe('2026-10-02 12:10 to 13:40 UTC');
    expect(t.getAttribute('data-time')).toBe('absolute');
    expect(t.getAttribute('title')).toMatch(/^Local time: 2026-10-02 \d{2}:\d{2} \S+ to 2026-10-02 \d{2}:\d{2} \S+$/);
  });

  it('reads one end as one time', async () => {
    // Negative control: a span with no end is one instant, with one local time.
    render(<UtcTime testId="t" iso="2026-10-02T12:10:00Z" to={null} seconds={false} />);
    const t = await screen.findByTestId('t');
    expect(t.textContent).toBe('2026-10-02 12:10 UTC');
    expect(t.getAttribute('title')).toBe(localTitle('2026-10-02T12:10:00Z'));
  });
});

describe('RelTime', () => {
  it('states the UTC time and the local time in the tooltip', async () => {
    const iso = new Date(Date.now() - 4 * 3_600_000).toISOString();
    render(<RelTime testId="r" iso={iso} what="Event" note="Recorded 2026-10-02 12:20 UTC." />);
    const r = await screen.findByTestId('r');
    expect(r.textContent).toBe('4h ago');
    expect(r.getAttribute('data-time')).toBe('relative');
    expect(r.getAttribute('title')).toMatch(
      /^Event \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC\. Local time: \d{4}-\d{2}-\d{2} \d{2}:\d{2} \S+\. Recorded 2026-10-02 12:20 UTC\.$/,
    );
  });

  it('keeps a label that the server wrote', async () => {
    render(<RelTime testId="r" iso="2026-10-02T12:10:28Z" text="14h" />);
    const r = await screen.findByTestId('r');
    expect(r.textContent).toBe('14h');
    expect(r.getAttribute('title')).toMatch(/^2026-10-02 12:10 UTC\. Local time: /);
  });

  it('names no time when it has none', async () => {
    // Negative control: no value, no tooltip.
    render(<RelTime testId="r" iso={null} text="—" />);
    const r = await screen.findByTestId('r');
    expect(r.getAttribute('title')).toBeNull();
    expect(r.getAttribute('dateTime')).toBeNull();
  });
});

// Round 4, C4: the zone that the analyst picks for the second clock of the top
// bar is the local time of the console. Each test names the zone that it
// reads, so it passes under any TZ of the machine.
describe('the local time of the console', () => {
  const ISO = '2026-10-02T12:10:28Z';
  const browserTitle = (iso: string) => `Local time: ${absoluteTime(iso, { timeZone: browserTimeZone() })}`;

  afterEach(() => {
    setSecondClock(SECOND_CLOCK_OFF);
  });

  it('states the picked zone in the tooltip of an absolute time', async () => {
    setSecondClock({ mode: 'zone', zone: 'Asia/Tokyo' });
    render(<UtcTime testId="t" iso={ISO} />);
    const t = await screen.findByTestId('t');
    // The text stays UTC.
    expect(t.textContent).toBe('2026-10-02 12:10:28 UTC');
    expect(t.getAttribute('title')).toBe(`Local time: ${absoluteTime(ISO, { timeZone: 'Asia/Tokyo' })}`);
    expect(t.getAttribute('title')).toMatch(/^Local time: 2026-10-02 21:10 \S+$/);
  });

  it('states the picked zone at both ends of a span', async () => {
    setSecondClock({ mode: 'zone', zone: 'America/Chicago' });
    render(<UtcTime testId="t" iso="2026-11-19T05:10:00Z" to="2026-11-19T06:40:00Z" seconds={false} />);
    expect((await screen.findByTestId('t')).getAttribute('title')).toBe(
      'Local time: 2026-11-18 23:10 CST to 2026-11-19 00:40 CST',
    );
  });

  it('states the picked zone in the tooltip of a relative time', async () => {
    setSecondClock({ mode: 'zone', zone: 'America/Chicago' });
    render(<RelTime testId="r" iso="2026-11-19T14:32:00Z" text="14h" what="Event" />);
    expect((await screen.findByTestId('r')).getAttribute('title')).toBe(
      'Event 2026-11-19 14:32 UTC. Local time: 2026-11-19 08:32 CST',
    );
  });

  it('follows a change of the zone on an open page with no reload', async () => {
    render(
      <>
        <UtcTime testId="t" iso={ISO} />
        <RelTime testId="r" iso={ISO} text="14h" />
      </>,
    );
    const t = await screen.findByTestId('t');
    const r = screen.getByTestId('r');
    expect(t.getAttribute('title')).toBe(browserTitle(ISO));
    act(() => setSecondClock({ mode: 'zone', zone: 'America/Chicago' }));
    expect(t.getAttribute('title')).toBe('Local time: 2026-10-02 07:10 CDT');
    expect(r.getAttribute('title')).toBe('2026-10-02 12:10 UTC. Local time: 2026-10-02 07:10 CDT');
    act(() => setSecondClock(SECOND_CLOCK_OFF));
    expect(t.getAttribute('title')).toBe(browserTitle(ISO));
  });

  it('states the zone of the browser for "Off" and for the local time of this browser', async () => {
    // Negative control: with no picked zone the tooltips read as before.
    render(
      <>
        <UtcTime testId="t" iso={ISO} />
        <RelTime testId="r" iso={ISO} text="14h" />
      </>,
    );
    const t = await screen.findByTestId('t');
    expect(t.getAttribute('title')).toBe(browserTitle(ISO));
    expect(screen.getByTestId('r').getAttribute('title')).toBe(`2026-10-02 12:10 UTC. ${browserTitle(ISO)}`);
    act(() => setSecondClock({ mode: 'browser' }));
    expect(t.getAttribute('title')).toBe(browserTitle(ISO));
    expect(screen.getByTestId('r').getAttribute('title')).toBe(`2026-10-02 12:10 UTC. ${browserTitle(ISO)}`);
  });

  it('gives the picked zone to a tooltip that a page builds by hand', () => {
    setSecondClock({ mode: 'zone', zone: 'America/Chicago' });
    expect(localTitle('2026-11-19T14:32:00Z')).toBe('Local time: 2026-11-19 08:32 CST');
    expect(timeTitle('2026-11-19T14:32:00Z')).toBe('2026-11-19 14:32 UTC. Local time: 2026-11-19 08:32 CST');
    // A caller that names a zone keeps it.
    expect(absoluteTime('2026-11-19T14:32:00Z', { timeZone: 'UTC' })).toBe('2026-11-19 14:32 UTC');
  });
});
