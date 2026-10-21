// The live half of the host page, read during a grid outage (dogfood
// 2026-10-19, R4-D5, R4-D8, R4-D9 and R4-D21).
//
// * The Users card read system.auth only and said "no host logs" on a
//   Windows domain controller with 9 logon users. It now names the datasets
//   it reads.
// * The Connections card divided 229 connections by 24 hours when 23 of the
//   hours held no data, and said "10 per hour".
// * The Volume chart had one bucket, and its start and end labels read the
//   same instant.
// * "last seen" was the start of the newest chart bucket.
// * The page never named the datasets behind the connection counts.
//
// Round 2 (V2-1): the 7d rate divided 224,199 connections by 8 day buckets of
// 24 hours, 192 hours, on a 168-hour window. The 24h series holds 25 buckets.
// Hours inside a grid gap with a few stray records counted as hours with data:
// "294 per hour" under a 20-hour gap strip. The rate now divides by the window
// hours that hold data, prorates the edge buckets and leaves out gap hours.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { absTime } from '../lib/timeRange';
import type { GridGap, HostActivity, VolumePoint } from '../lib/types';
import { lastSeenOf } from '../screens/HostDetail';
import { HostActivityRow } from './HostActivityRow';
import { HostKpis, connectionRate } from './HostKpis';

const IP = '192.0.2.10';
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

// The end of the window the server read: an hour boundary, so that 24
// hourly buckets fill the 24h window exactly. Seeded relative to now.
const END = Math.floor(Date.now() / HOUR) * HOUR;

const hourly = (counts: number[]): VolumePoint[] =>
  counts.map((events, i) => ({
    ts: new Date(END - 24 * HOUR + i * HOUR).toISOString(),
    events,
  }));

const gap = (start: number, end: number | null): GridGap => ({
  id: 2,
  source: 'sweep',
  plane: null,
  started_at: new Date(start).toISOString(),
  ended_at: end === null ? null : new Date(end).toISOString(),
  open: end === null,
  duration_s: ((end ?? start) - start) / 1000,
  detail: '',
});

const activity = (over: Partial<HostActivity> = {}): HostActivity => ({
  peers: [{ ip: '192.0.2.20', hostname: null, direction: 'out', ports: [443], events: 10, alerted: false }],
  volume: hourly(Array.from({ length: 24 }, () => 0)),
  window_end: new Date(END).toISOString(),
  users: null,
  alerts_7d: 0,
  latest_investigation: null,
  peers_truncated: false,
  users_truncated: false,
  ...over,
});

const kpis = (a: HostActivity, range: '24h' | '7d' = '24h', gaps?: GridGap[]) =>
  render(
    <MemoryRouter>
      <HostKpis ip={IP} services={[]} activity={a} state="ok" range={range} gaps={gaps} />
    </MemoryRouter>,
  );

const row = (a: HostActivity, range: '24h' | '7d' = '24h') =>
  render(
    <MemoryRouter>
      <HostActivityRow ip={IP} activity={a} state="ok" error={null} loading={false} range={range} onRetry={() => {}} />
    </MemoryRouter>,
  );

describe('the connection rate', () => {
  it('divides by the hours that hold data and says so', () => {
    const counts = Array.from({ length: 24 }, (_, i) => (i >= 20 ? 100 : 0));
    kpis(activity({ volume: hourly(counts) }));
    expect(screen.getByTestId('kpi-events-rate').textContent).toBe(
      '100 per hour in and out over the 4 hours with data',
    );
  });

  it('keeps the plain rate when every hour holds data', () => {
    // NEGATIVE CONTROL: no gap, no denominator words.
    kpis(activity({ volume: hourly(Array.from({ length: 24 }, () => 10)) }));
    expect(screen.getByTestId('kpi-events-rate').textContent).toBe('10 per hour in and out');
  });

  it('counts the hours that hold data on the 7d window', () => {
    // Day buckets start at midnight UTC. The window ends at 09:15 and starts
    // 168 hours earlier, so it touches 8 day buckets: two of them in part.
    const end = Math.floor(Date.now() / DAY) * DAY + 9 * HOUR + 15 * 60_000;
    const first = Math.floor((end - 7 * DAY) / DAY) * DAY;
    const days: VolumePoint[] = Array.from({ length: 8 }, (_, i) => ({
      ts: new Date(first + i * DAY).toISOString(),
      events: 21_000,
    }));
    // 168 000 records over 168 hours. The old rule divided by 8 days of 24 hours.
    expect(connectionRate(days, '7d', { end })).toEqual({
      perHour: 1000,
      hours: 168,
      windowHours: 168,
      gapHours: 0,
    });
    // Three days with data: the newest day holds 9.25 hours of the window.
    const late = days.map((point, i) => ({ ...point, events: i >= 5 ? point.events : 0 }));
    expect(connectionRate(late, '7d', { end }).hours).toBe(57.25);
  });

  it('prorates the two edge buckets of the 25-bucket 24h series', () => {
    const end = END + 15 * 60_000;
    const volume: VolumePoint[] = Array.from({ length: 25 }, (_, i) => ({
      ts: new Date(END - 24 * HOUR + i * HOUR).toISOString(),
      events: 100,
    }));
    const rate = connectionRate(volume, '24h', { end });
    expect(rate.hours).toBe(24);
    expect(rate.perHour).toBe(Math.round(2_500 / 24));
  });

  it('leaves out the hours of a grid gap, with the stray records in them', () => {
    // The window ends 15 minutes past the hour. A gap covers the 20 hours
    // before the newest bucket. Each gap hour holds 5 stray records.
    const end = END + 15 * 60_000;
    const volume: VolumePoint[] = Array.from({ length: 25 }, (_, i) => {
      const ts = END - 24 * HOUR + i * HOUR;
      const inGap = ts >= END - 20 * HOUR && ts < END;
      return { ts: new Date(ts).toISOString(), events: inGap ? 5 : 300 };
    });
    const gaps = [gap(END - 20 * HOUR, END)];
    // 0.75 + 3 + 0.25 hours hold data outside the gap: 1,500 records.
    expect(connectionRate(volume, '24h', { end, gaps })).toEqual({
      perHour: 375,
      hours: 4,
      windowHours: 24,
      gapHours: 20,
    });
    // NEGATIVE CONTROL: the same series with no gap on record.
    expect(connectionRate(volume, '24h', { end }).hours).toBe(24);
  });

  it('reads an open gap to the end of the window', () => {
    const end = END + 15 * 60_000;
    const volume = hourly(Array.from({ length: 24 }, () => 10));
    const rate = connectionRate(volume, '24h', { end, gaps: [gap(END - 2 * HOUR, null)] });
    expect(rate.gapHours).toBe(2.25);
    expect(rate.hours).toBe(21.75);
  });

  it('states the rate over the hours outside the gap and names the gap hours', () => {
    const counts = Array.from({ length: 24 }, (_, i) => (i < 4 ? 100 : 2));
    kpis(activity({ volume: hourly(counts) }), '24h', [gap(END - 20 * HOUR, END)]);
    const rate = screen.getByTestId('kpi-events-rate');
    expect(rate.textContent).toBe('100 per hour in and out over the 4 hours with data');
    expect(rate.getAttribute('title')).toContain('The rate leaves out 20 hours of grid gaps.');
  });
});

describe('the volume chart', () => {
  it('ends its axis at the end of the newest bucket', () => {
    const volume = [{ ts: '2026-10-19T06:00:00Z', events: 229 }];
    row(activity({ volume }));
    const chart = screen.getByTestId('host-volume');
    expect(within(chart).getByTestId('volume-start').textContent).toBe(absTime('2026-10-19T06:00:00Z'));
    expect(within(chart).getByTestId('volume-end').textContent).toBe(absTime('2026-10-19T07:00:00Z'));
  });

  it('names the datasets behind the connection counts', () => {
    row(activity({ volume: hourly([5, 6]), conn_datasets: ['zeek.conn', 'network_traffic.flow'] }));
    expect(screen.getByTestId('volume-datasets').textContent).toBe(
      'The counts come from zeek.conn and network_traffic.flow.',
    );
  });

  it('names no dataset for an older server', () => {
    // NEGATIVE CONTROL: no field, no claim.
    row(activity({ volume: hourly([5, 6]) }));
    expect(screen.queryByTestId('volume-datasets')).toBeNull();
  });
});

describe('the users card', () => {
  it('names the datasets it reads when it finds no logon', () => {
    row(activity({ users: null, auth_datasets: ['system.security', 'system.auth'] }));
    const users = screen.getByTestId('host-users');
    expect(users.textContent).toContain('This card reads system.security and system.auth.');
    expect(users.textContent).toContain('These datasets hold no logon for this address in the last 24h.');
    expect(users.textContent).not.toMatch(/cannot tell the two apart/);
  });

  it('names the datasets under a list of accounts', () => {
    row(
      activity({
        users: [{ name: 'alice', events: 4, last_seen: '2026-10-19T06:10:00Z' }],
        auth_datasets: ['system.security', 'system.auth'],
      }),
    );
    expect(screen.getByTestId('users-datasets').textContent).toBe(
      'From system.security and system.auth.',
    );
  });
});

describe('last seen', () => {
  it('reads the newest event over the newest bucket', () => {
    const newest = new Date(Date.now() - 4 * 60_000).toISOString();
    const volume = [{ ts: new Date(Date.now() - 40 * 60_000).toISOString(), events: 300 }];
    expect(lastSeenOf(activity({ volume, newest_event: newest }))).toBe(newest);
  });

  it('falls back to the newest bucket on an older server', () => {
    // NEGATIVE CONTROL: no newest_event, the bucket stands.
    const bucket = new Date(Date.now() - 40 * 60_000).toISOString();
    expect(lastSeenOf(activity({ volume: [{ ts: bucket, events: 300 }] }))).toBe(bucket);
    expect(lastSeenOf(null)).toBeNull();
  });
});
