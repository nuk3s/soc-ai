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
  { failed = false, scheduleEnabled = false as boolean | null, searchActive = false } = {},
) =>
  render(
    <MemoryRouter>
      <HostsSummary
        summary={summary}
        failed={failed}
        linkFor={(patch) => listHref(patch)}
        scheduleEnabled={scheduleEnabled}
        searchActive={searchActive}
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
    expect(href('attention-all')).toBe('/hosts?health=attention&activity=all');
    // A card at 0 is a filter too, so its click shows an empty list.
    expect(href('card-conflicts')).toBe('/hosts?conflict=yes&activity=all');
    // The card names its number for a screen reader.
    expect(screen.getByRole('link', { name: /^With an agent: 12\./ })).toBeTruthy();
  });

  it('does not count a conflict twice', () => {
    // The old Needs attention card summed conflicts, and the Conflicts card
    // counted them again (U17). The wire's needs_attention is the number.
    mount(SUMMARY);
    expect(within(screen.getByTestId('sum-attention')).getByText('5')).toBeTruthy();
    expect(within(screen.getByTestId('sum-conflicts')).getByText('2')).toBeTruthy();
  });
});

// Dogfood 2026-10-06: the card read "37" with the sub "3 broken or never
// built", and its click listed the 3. The number now lists the machines it
// counts, and each part lists its own.
describe('HostsSummary: Needs attention lists what it counts', () => {
  it('splits the number into its linked parts', () => {
    mount({ ...SUMMARY, needs_attention: 37, out_of_date: 34, never_built: 3, build_failed: 3 });
    const card = screen.getByTestId('sum-attention');
    expect(card.textContent).toMatch(/34 out of date, 3 failed to build/);
    expect(card.getAttribute('title')).toBe(
      '37 need attention: 34 out of date, 3 failed to build. Each number lists its machines.',
    );
    expect(screen.getByTestId('attention-all').textContent).toBe('37');
    expect(screen.getByTestId('attention-stale').getAttribute('href')).toBe('/hosts?health=stale&activity=all');
    expect(screen.getByTestId('attention-failed').getAttribute('href')).toBe('/hosts?health=broken&activity=all');
  });

  // Dogfood 2026-10-19 (R4-D16): "3 never built" counted 3 machines whose
  // last build FAILED. never_built is every machine with no clean build, and
  // build_failed is the part whose last build failed.
  it('does not call a failed build "never built"', () => {
    mount({ ...SUMMARY, needs_attention: 37, out_of_date: 34, never_built: 3, build_failed: 3 });
    const card = screen.getByTestId('sum-attention');
    expect(card.textContent).not.toMatch(/never built/);
    expect(screen.queryByTestId('attention-never-built')).toBeNull();
  });

  it('names the failed builds and the machines never built apart', () => {
    mount({ ...SUMMARY, needs_attention: 9, out_of_date: 4, never_built: 5, build_failed: 2 });
    expect(screen.getByTestId('attention-failed').textContent).toBe('2 failed to build');
    expect(screen.getByTestId('attention-never-built').textContent).toBe('3 never built');
    expect(screen.getByTestId('attention-never-built').getAttribute('href')).toBe(
      '/hosts?health=broken&activity=all',
    );
    expect(screen.getByTestId('sum-attention').getAttribute('title')).toBe(
      '9 need attention: 4 out of date, 2 failed to build, 3 never built. Each number lists its machines.',
    );
  });

  it('shows a part only when it counts a machine', () => {
    mount({ ...SUMMARY, needs_attention: 5, out_of_date: 5, never_built: 0, build_failed: 0 });
    expect(screen.getByTestId('sum-attention').textContent).toMatch(/5 out of date/);
    expect(screen.queryByTestId('attention-failed')).toBeNull();
    expect(screen.queryByTestId('attention-never-built')).toBeNull();
    expect(screen.queryByTestId('attention-no-clean-build')).toBeNull();
  });

  it('keeps one part for an older server that sends no build_failed', () => {
    // An older server cannot tell a failed build from no build.
    mount({ ...SUMMARY, needs_attention: 37, out_of_date: 34, never_built: 3 });
    const part = screen.getByTestId('attention-no-clean-build');
    expect(part.textContent).toBe('3 have no clean build');
    expect(part.getAttribute('href')).toBe('/hosts?health=broken&activity=all');
    expect(screen.getByTestId('sum-attention').textContent).not.toMatch(/never built|failed to build/);
  });

  it('derives the out-of-date part from an older server', () => {
    const { out_of_date: _ignored, ...older } = { ...SUMMARY, out_of_date: undefined };
    mount({ ...older, needs_attention: 7, never_built: 2 });
    expect(screen.getByTestId('attention-stale').textContent).toBe('5 out of date');
  });

  it('nests no link in a link', () => {
    // NEGATIVE CONTROL: three links in one card, so the card is not a link.
    mount({ ...SUMMARY, needs_attention: 37, out_of_date: 34, never_built: 3, build_failed: 1 });
    expect(screen.getByTestId('card-attention').tagName).toBe('DIV');
    expect(screen.getByTestId('card-attention').querySelectorAll('a a')).toHaveLength(0);
  });
});

describe('HostsSummary: the search does not filter the cards', () => {
  it('says so while a search is active', () => {
    mount(SUMMARY, { searchActive: true });
    expect(screen.getByTestId('hosts-summary-scope').textContent).toBe(
      'The cards and the role bar count every machine. The search does not filter them.',
    );
  });

  it('says nothing without a search', () => {
    // NEGATIVE CONTROL
    mount(SUMMARY);
    expect(screen.queryByTestId('hosts-summary-scope')).toBeNull();
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
    expect(screen.getByTestId('role-legend-low_confidence').textContent).toMatch(/weak guess\s*9/);
  });

  it('names its population and lists no bucket as a role', () => {
    // Dogfood 2026-10-06: "stale 6 · unknown 31" read as two roles, beside a
    // menu that counted another population.
    mount(SUMMARY);
    expect(screen.getByTestId('role-bar-scope').textContent).toBe(
      'across all 144 machines, quiet ones too',
    );
    const unconfirmed = screen.getByTestId('role-bar-unconfirmed');
    expect(unconfirmed.textContent).toMatch(/^No confirmed role:/);
    expect(within(unconfirmed).getByTestId('role-legend-stale').textContent).toMatch(/old guess\s*2/);
    expect(within(unconfirmed).getByTestId('role-legend-unknown').textContent).toMatch(/no role\s*103/);
    // NEGATIVE CONTROL: a real role stays outside the unconfirmed group.
    expect(within(unconfirmed).queryByTestId('role-legend-server')).toBeNull();
    expect(screen.getByTestId('role-bar').textContent).not.toMatch(/\bstale\b/);
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
