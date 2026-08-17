// The host list's network strip: four KPI cards and a role-distribution bar.
// The rules it inherits are the ones this project has already paid for:
//   * a failed read never renders a zero — "0 hosts" is a claim about the
//     network, and it is false exactly when the endpoint is down; the cards
//     show the shared dash instead;
//   * a count is a door or it is a caption: broken builds and open
//     disagreements link to the views that show THEM, and no link exists at
//     zero (the untriaged-tile defect in miniature);
//   * the numbers date themselves, because the schedule is off by default and
//     a week-old count reads exactly like a fresh one.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { roleRail } from '../lib/hostColors';
import type { DossierSummary } from '../lib/types';
import { HostsSummary, roleSlices } from './HostsSummary';

const SUMMARY: DossierSummary = {
  hosts: 147,
  never_built: 3,
  named: 25,
  reporting: 13,
  conflicts: 2,
  roles: { server: 12, workstation: 30, hypervisor: 2 },
  last_built_at: new Date(Date.now() - 4 * 3_600_000).toISOString(),
  schedule_enabled: false,
};

const mount = (summary: DossierSummary | null, failed = false, queueVisible = false) =>
  render(
    <MemoryRouter>
      <HostsSummary summary={summary} failed={failed} queueVisible={queueVisible} />
    </MemoryRouter>,
  );

describe('HostsSummary — the cards', () => {
  it('states the network with its arithmetic intact', () => {
    mount(SUMMARY);
    const hosts = screen.getByTestId('sum-hosts');
    expect(within(hosts).getByText('147')).toBeTruthy();
    // Named coverage rides the Hosts card: both halves, so the sub cannot
    // claim more names than the table below shows.
    expect(hosts.textContent).toMatch(/25 named · 122 unnamed/);

    const reporting = screen.getByTestId('sum-reporting');
    expect(within(reporting).getByText('13')).toBeTruthy();
    expect(reporting.textContent).toMatch(/with agent logs/);
  });

  it('names the agent gap where the number alone would hide it', () => {
    mount(SUMMARY);
    const reporting = screen.getByTestId('sum-reporting');
    expect(reporting.getAttribute('title')).toContain('134');
  });

  it('sums broken and review into the attention card, doors attached', () => {
    mount(SUMMARY);
    const attention = screen.getByTestId('sum-attention');
    expect(within(attention).getByText('5')).toBeTruthy(); // 3 broken + 2 review
    const broken = within(attention).getByTestId('sum-broken');
    expect(broken.textContent).toMatch(/3 broken or never built/);
    expect(broken).toHaveAttribute('href', '/hosts?health=broken');
    const review = within(attention).getByTestId('sum-review');
    expect(review.textContent).toMatch(/2 need review/);
    expect(review).toHaveAttribute('href', '/hosts?conflicts=1');
  });

  it('offers no broken door when nothing is broken', () => {
    mount({ ...SUMMARY, never_built: 0 });
    expect(screen.queryByTestId('sum-broken')).toBeNull();
  });

  it('carries the pending count on the conflicts card with its own door', () => {
    mount(SUMMARY);
    const card = screen.getByTestId('sum-conflicts');
    expect(within(card).getByText('2')).toBeTruthy();
    expect(within(card).getByRole('link', { name: /review queue/i })).toHaveAttribute(
      'href',
      '/hosts?conflicts=1',
    );
  });

  it('gives up the review doors while the banner already carries the action', () => {
    // Same number, same words, same disclosure, 40px apart is one control that
    // looks like two — the counts stay, the duplicate doors go.
    mount(SUMMARY, false, true);
    const review = screen.getByTestId('sum-review');
    expect(review.textContent).toMatch(/2 need review/);
    expect(review.tagName.toLowerCase()).not.toBe('a');
    const card = screen.getByTestId('sum-conflicts');
    expect(within(card).queryByRole('link')).toBeNull();
    expect(card.textContent).toMatch(/queue below/i);
  });

  it('says nothing about review when the lanes agree', () => {
    mount({ ...SUMMARY, conflicts: 0 });
    expect(screen.queryByTestId('sum-review')).toBeNull();
    const card = screen.getByTestId('sum-conflicts');
    expect(within(card).queryByRole('link')).toBeNull();
    expect(card.textContent).toMatch(/lanes agree/i);
  });
});

describe('HostsSummary — the role bar', () => {
  it('draws one proportional segment per resolved role, biggest first', () => {
    mount(SUMMARY);
    const bar = screen.getByTestId('role-bar');
    const workstation = within(bar).getByTestId('role-seg-workstation');
    expect(workstation.getAttribute('style')).toContain('flex-grow: 30');
    expect(workstation.className).toContain(roleRail('workstation'));
    // Legend labels are readable words with counts — a 2%-wide segment cannot
    // carry its own text.
    expect(bar.textContent).toContain('workstation');
    expect(bar.textContent).toContain('30');
    expect(bar.textContent).toContain('server');
    expect(bar.textContent).toContain('hypervisor');
  });

  it('draws the unresolved remainder last, in gray, and never oversells it', () => {
    mount(SUMMARY);
    const bar = screen.getByTestId('role-bar');
    const segs = within(bar)
      .getAllByTestId(/^role-seg-/)
      .map((el) => el.getAttribute('data-testid'));
    expect(segs[0]).toBe('role-seg-workstation'); // 30 first
    expect(segs[segs.length - 1]).toBe('role-seg-unknown');
    const unknown = within(bar).getByTestId('role-seg-unknown');
    // 147 hosts, 44 resolved → 103 unresolved, wearing the neutral rail.
    expect(unknown.getAttribute('style')).toContain('flex-grow: 103');
    expect(unknown.className).toContain(roleRail(null));
  });

  it('folds a literal "unknown" role into the gray remainder, not a second gray', () => {
    // The classifier can emit role="unknown"; to a reader that IS the
    // remainder, and two adjacent gray segments would claim a distinction the
    // data is not making.
    const slices = roleSlices({ ...SUMMARY, roles: { server: 10, unknown: 5 } });
    expect(slices).toEqual([
      { role: 'server', count: 10 },
      { role: null, count: 137 },
    ]);
  });

  it('speaks the classifier vocabulary in words, not schema tokens', () => {
    mount({ ...SUMMARY, roles: { domain_controller: 3 } });
    const bar = screen.getByTestId('role-bar');
    expect(bar.textContent).toContain('domain controller');
    expect(bar.textContent).not.toContain('domain_controller');
  });

  it('draws no bar over an empty table', () => {
    mount({ ...SUMMARY, hosts: 0, named: 0, reporting: 0, roles: {} });
    expect(screen.queryByTestId('role-bar')).toBeNull();
  });
});

describe('HostsSummary — degraded reads', () => {
  it('renders dashes and no zeros when the count cannot be read', () => {
    const { container } = mount(null, true);
    const bar = screen.getByTestId('hosts-summary');
    expect(bar.textContent).toMatch(/could not be read/i);
    // The table below is a separate query and very likely fine — say so.
    expect(bar.textContent).toMatch(/unaffected/i);
    expect(bar.textContent).not.toMatch(/\b0\b/);
    // Every card degrades to the shared dash, never a confident number.
    for (const id of ['sum-hosts', 'sum-reporting', 'sum-attention', 'sum-conflicts']) {
      expect(within(screen.getByTestId(id)).getAllByText('—').length).toBeGreaterThan(0);
    }
    expect(container.querySelectorAll('a').length).toBe(0);
  });

  it('distinguishes a read still in flight from one that failed', () => {
    mount(null, false);
    const bar = screen.getByTestId('hosts-summary');
    expect(bar.textContent).toMatch(/counting/i);
    expect(bar.textContent).not.toMatch(/could not be read/i);
  });

  it('keeps the last good numbers when a refresh fails, and dates them honestly', () => {
    // useAsync keeps prior data on a foreground failure, so a failed re-count
    // arrives as a populated summary WITH failed set. Blanking would throw
    // away a read the operator had; dating it as current would lie.
    mount(SUMMARY, true);
    const bar = screen.getByTestId('hosts-summary');
    expect(within(bar).getByText('147')).toBeTruthy();
    expect(bar.textContent).toMatch(/could not refresh/i);
    expect(bar.textContent).toMatch(/last swept 4h ago/i);
  });
});

describe('HostsSummary — the counts are dated, once', () => {
  it('says how old the numbers are, from the data`s own clock', () => {
    mount(SUMMARY);
    expect(screen.getByTestId('hosts-summary').textContent).toMatch(/last swept 4h ago/i);
  });

  it('says the schedule is off, and where to turn it on', () => {
    mount(SUMMARY);
    const line = screen.getByTestId('hosts-summary');
    expect(line.textContent).toMatch(/automatic sweeps are off/i);
    expect(within(line).getByRole('link', { name: /automatic sweeps are off/i })).toHaveAttribute(
      'href',
      '/config#host-dossier',
    );
  });

  it('stays quiet about the schedule when it is running', () => {
    mount({ ...SUMMARY, schedule_enabled: true });
    expect(screen.getByTestId('hosts-summary').textContent).not.toMatch(/sweeps are off/i);
  });

  it('says never swept rather than dating the counts to nothing', () => {
    mount({ ...SUMMARY, last_built_at: null });
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
