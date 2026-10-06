// The machine list's strip: six cards and a role bar, from GET /hosts/summary.
// The rules it keeps:
//   * every card and every role segment is a link to the list filter it
//     counts, the "unknown" bucket included (dogfood 2026-10-02, U9, U16);
//   * the bar draws the counts the wire sends. The client derives no
//     remainder, so the bar and the filter cannot disagree;
//   * a failed read never renders a zero. The cards show the shared dash;
//   * the numbers date themselves.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { listHref } from '../lib/hostsList';
import { absTime } from '../lib/timeRange';
import type { MachineSummary } from '../lib/types';
import { HostsSummary, roleSlices } from './HostsSummary';

const SUMMARY: MachineSummary = {
  machines: 144,
  addresses: 205,
  with_agent: 12,
  without_agent: 132,
  new_7d: 4,
  named: 60,
  unnamed: 84,
  roles: { server: 20, workstation: 7, hypervisor: 3, low_confidence: 9, stale: 2, unknown: 103 },
  needs_attention: 5,
  conflicts: 2,
  never_built: 3,
  last_sweep_at: new Date(Date.now() - 4 * 3_600_000).toISOString(),
  stale_hours: null,
};

const mount = (
  summary: MachineSummary | null,
  { failed = false, scheduleEnabled = false as boolean | null } = {},
) =>
  render(
    <MemoryRouter>
      <HostsSummary
        summary={summary}
        failed={failed}
        linkFor={(patch) => listHref(patch)}
        brokenHref="/hosts?health=broken"
        conflictsHref="/hosts?conflicts=1"
        scheduleEnabled={scheduleEnabled}
      />
    </MemoryRouter>,
  );

describe('HostsSummary — the cards', () => {
  it('counts machines, with the named split', () => {
    mount(SUMMARY);
    const card = screen.getByTestId('sum-machines');
    expect(within(card).getByText('144')).toBeTruthy();
    expect(card.textContent).toMatch(/60 named · 84 unnamed/);
  });

  it('makes each card a link to the filter it counts', () => {
    mount(SUMMARY);
    const href = (id: string) => screen.getByTestId(id).getAttribute('href');
    expect(href('card-machines')).toBe('/hosts?activity=all');
    expect(href('card-with-agent')).toBe('/hosts?agent=yes&activity=all');
    expect(href('card-without-agent')).toBe('/hosts?agent=no&activity=all');
    expect(href('card-new')).toBe('/hosts?seen=new&activity=all');
    expect(href('card-attention')).toBe('/hosts?health=broken');
    expect(href('card-conflicts')).toBe('/hosts?conflicts=1');
    // The card names its number for a screen reader.
    expect(screen.getByRole('link', { name: /^With an agent: 12\./ })).toBeTruthy();
  });

  it('does not count a conflict twice', () => {
    // The old Needs attention card summed conflicts, and the Conflicts card
    // counted them again (U17). The wire's needs_attention is the number.
    mount(SUMMARY);
    expect(within(screen.getByTestId('sum-attention')).getByText('5')).toBeTruthy();
    expect(screen.getByTestId('sum-attention').textContent).toMatch(/3 broken or never built/);
    expect(within(screen.getByTestId('sum-conflicts')).getByText('2')).toBeTruthy();
  });
});

describe('HostsSummary — the role bar', () => {
  it('draws the wire counts: roles biggest first, then the three buckets', () => {
    const slices = roleSlices(SUMMARY);
    expect(slices.map((s) => `${s.filter}:${s.count}`)).toEqual([
      'server:20',
      'workstation:7',
      'hypervisor:3',
      'low_confidence:9',
      'stale:2',
      'unknown:103',
    ]);
  });

  it('derives no remainder the wire did not send', () => {
    // The old bar computed "unknown" as machines minus the roles, and the
    // filter for it returned 0 rows while the bar said 250 (U9).
    const slices = roleSlices({ ...SUMMARY, roles: { server: 20 } });
    expect(slices.map((s) => s.filter)).toEqual(['server']);
  });

  it('links every segment and legend entry to its role filter, unknown too', () => {
    mount(SUMMARY);
    expect(screen.getByTestId('role-seg-unknown').getAttribute('href')).toBe(
      '/hosts?role=unknown&activity=all',
    );
    expect(screen.getByTestId('role-seg-server').getAttribute('href')).toBe(
      '/hosts?role=server&activity=all',
    );
    expect(screen.getByTestId('role-legend-low_confidence').getAttribute('href')).toBe(
      '/hosts?role=low_confidence&activity=all',
    );
    expect(screen.getByTestId('role-legend-low_confidence').textContent).toMatch(/low confidence\s*9/);
  });

  it('draws no bar over an empty census', () => {
    mount({ ...SUMMARY, machines: 0, roles: {} });
    expect(screen.queryByTestId('role-bar')).toBeNull();
  });
});

describe('HostsSummary — degraded reads', () => {
  it('renders dashes and no zeros when the count cannot be read', () => {
    mount(null, { failed: true });
    const bar = screen.getByTestId('hosts-summary');
    expect(bar.textContent).toMatch(/could not be read/i);
    expect(bar.textContent).toMatch(/still works/i);
    expect(bar.textContent).not.toMatch(/\b0\b/);
    for (const id of ['sum-machines', 'sum-with-agent', 'sum-without-agent', 'sum-new', 'sum-attention', 'sum-conflicts']) {
      expect(within(screen.getByTestId(id)).getAllByText('—').length).toBeGreaterThan(0);
    }
  });

  it('distinguishes a read still in flight from one that failed', () => {
    mount(null);
    const bar = screen.getByTestId('hosts-summary');
    expect(bar.textContent).toMatch(/counting/i);
    expect(bar.textContent).not.toMatch(/could not be read/i);
  });

  it('keeps the last good numbers when a refresh fails, and dates them', () => {
    mount(SUMMARY, { failed: true });
    const bar = screen.getByTestId('hosts-summary');
    expect(within(bar).getByText('144')).toBeTruthy();
    expect(bar.textContent).toMatch(/could not refresh/i);
    expect(bar.textContent).toMatch(/last swept 4h ago/i);
  });
});

describe('HostsSummary — the counts are dated, once', () => {
  it('says the schedule is off, and where to turn it on', () => {
    mount(SUMMARY, { scheduleEnabled: false });
    const line = screen.getByTestId('hosts-summary');
    expect(within(line).getByRole('link', { name: /automatic sweeps are off/i })).toHaveAttribute(
      'href',
      '/config#host-dossier',
    );
  });

  // The list reads the last sweep and the machine page reads live activity.
  // The line dates the list (range dogfood 2026-10-05, M5).
  it('dates the list beside the schedule line when the schedule is off', () => {
    mount(SUMMARY, { scheduleEnabled: false });
    const asOf = screen.getByTestId('hosts-as-of');
    expect(asOf.textContent).toMatch(/^the list shows the state as of /);
    expect(asOf.getAttribute('title')).toContain('The machine page shows live activity.');
  });

  // N6 of the 2026-10-05 verification. The note read "Oct 02, 2026, 08:10:28
  // AM" for a sweep at 12:10 UTC, with no zone.
  it('states the time zone of the date it gives', () => {
    mount(SUMMARY, { scheduleEnabled: false });
    const asOf = screen.getByTestId('hosts-as-of');
    expect(asOf.textContent).toBe(
      `the list shows the state as of ${absTime(SUMMARY.last_sweep_at, { zone: true })}`,
    );
    const zone = new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' })
      .formatToParts(new Date(SUMMARY.last_sweep_at!))
      .find((p) => p.type === 'timeZoneName')!.value;
    expect(asOf.textContent!.endsWith(zone)).toBe(true);
  });

  it('adds no date when the schedule runs', () => {
    mount(SUMMARY, { scheduleEnabled: true });
    expect(screen.queryByTestId('hosts-as-of')).toBeNull();
  });

  it('stays quiet about the schedule when it runs, or when the screen does not know', () => {
    mount(SUMMARY, { scheduleEnabled: true });
    expect(screen.getByTestId('hosts-summary').textContent).not.toMatch(/sweeps are off/i);
  });

  it('says never swept rather than dating the counts to nothing', () => {
    mount({ ...SUMMARY, last_sweep_at: null });
    expect(screen.getByTestId('hosts-summary').textContent).toMatch(/never swept/i);
  });
});

describe('HostsSummary — house style', () => {
  it('takes every colour from the token set', () => {
    const { container } = mount(SUMMARY);
    expect(container.innerHTML).not.toMatch(/#[0-9a-fA-F]{3}/);
    expect(container.innerHTML).not.toMatch(/rgba?\(/);
  });
});
