// Runs made inside the page window decide the verdict of a group (owner rule,
// 2026-10-14). Everything on a page follows the time filter of the page, and
// the verdict of a group reached back seven days past a 24 hour window. A
// group with no run in the window keeps the older verdict that covers it, and
// the row says "inherited" with the age of that verdict.
//
// The verdict filter, the verdict sort, the "untriaged" count, the "Needs
// decision" chip and the row pill read one helper, the same one the Dashboard
// breakdown reads.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { ShellProvider } from '../shell/ShellContext';
import type { AlertGroup } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn(),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
  getAlertGroupEvents: vi.fn().mockResolvedValue([]),
  getInvestigation: vi.fn(() => new Promise(() => {})),
}));

import { getAlerts } from '../lib/api';
import { queueOf } from '../test/alertQueue';
import { Alerts } from './Alerts';

const daysAgo = (n: number): string => new Date(Date.now() - n * 86_400_000).toISOString();

const group = (id: string, over: Partial<AlertGroup>): AlertGroup => ({
  id,
  name: `ET TEST ${id}`,
  kind: 'suricata',
  sev: 'medium',
  count: 3,
  verdict: 'false_positive',
  conf: 0.9,
  latest: '2m ago',
  inherited: false,
  invId: `INV-${id}`,
  events: [],
  verdictCounts: {},
  worstVerdict: null,
  worstConf: null,
  worstInvId: null,
  windowVerdict: null,
  windowConf: null,
  windowInvId: null,
  verdictAt: daysAgo(0.1),
  ...over,
});

/** A true positive in the window, after which false positives came. */
const WIN_TP = group('win-tp', {
  windowVerdict: 'true_positive',
  windowConf: 0.62,
  windowInvId: 'INV-TP',
  verdictCounts: { false_positive: 2, true_positive: 1 },
  worstVerdict: 'true_positive',
  worstConf: 0.62,
  worstInvId: 'INV-TP',
});
/** The standing true positive ran after the end of a custom window. */
const OUT_TP = group('out-tp', {
  verdict: 'true_positive',
  conf: 0.62,
  windowVerdict: 'false_positive',
  windowConf: 0.9,
  windowInvId: 'INV-FP',
  verdictCounts: { false_positive: 2 },
});
/** No run in the window. The false positive is three days old. */
const INH_FP = group('inh-fp', { invId: 'INV-OLD', verdictAt: daysAgo(3) });
const NEW = group('new', { verdict: 'untriaged', conf: null, invId: undefined, verdictAt: null });
const WIN_NMI = group('win-nmi', {
  windowVerdict: 'needs_more_info',
  windowConf: 0.5,
  windowInvId: 'INV-NMI',
  verdictCounts: { false_positive: 1, needs_more_info: 1 },
});
const OLD_NMI = group('old-nmi', {
  verdict: 'needs_more_info',
  conf: 0.5,
  windowVerdict: 'false_positive',
  windowConf: 0.9,
  windowInvId: 'INV-FP3',
  verdictCounts: { false_positive: 1 },
});

const mountAt = (url: string, groups: AlertGroup[]) => {
  vi.mocked(getAlerts).mockResolvedValue(queueOf(groups));
  render(
    <MemoryRouter initialEntries={[url]}>
      <ShellProvider>
        <Alerts />
      </ShellProvider>
    </MemoryRouter>,
  );
};

const row = async (g: AlertGroup) =>
  (await screen.findByText(g.name)).closest('[data-group-key]') as HTMLElement;

describe('the list reads the window verdict of each group', () => {
  it('lists a true positive of the window under the true-positive filter', async () => {
    mountAt('/alerts?range=24h&hide_acked=false&verdict=true_positive', [OUT_TP, WIN_TP]);
    expect(await screen.findByText(WIN_TP.name)).toBeTruthy();
    // NEGATIVE CONTROL. A true positive from outside the window does not count.
    expect(screen.queryByText(OUT_TP.name)).toBeNull();
  });

  it('lists an inherited false positive under the false-positive filter', async () => {
    // The Dashboard tile counts the inherited group, so the list it opens holds it.
    mountAt('/alerts?range=24h&hide_acked=false&verdict=false_positive', [WIN_TP, OUT_TP, INH_FP]);
    expect(await screen.findByText(INH_FP.name)).toBeTruthy();
    expect(screen.getByText(OUT_TP.name)).toBeTruthy();
    expect(screen.queryByText(WIN_TP.name)).toBeNull();
  });

  it('sorts by the window verdict', async () => {
    mountAt('/alerts?range=24h&sort=verdict:desc', [OUT_TP, WIN_TP]);
    const win = await screen.findByText(WIN_TP.name);
    const out = screen.getByText(OUT_TP.name);
    // OUT_TP comes first in the response and holds a standing true positive.
    // Only the window verdict moves WIN_TP above it.
    expect(win.compareDocumentPosition(out) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('counts the untriaged groups by the verdict each group counts under', async () => {
    mountAt('/alerts?range=24h&hide_acked=false', [NEW, INH_FP, WIN_TP]);
    await screen.findByText(NEW.name);
    expect(screen.getByText(/untriaged ·/).textContent).toBe('1 untriaged · 3 detections · 9 events in window');
  });

  it('puts a group under Needs decision by its window verdict', async () => {
    mountAt('/alerts?range=24h&hide_acked=false&view=decision', [OLD_NMI, WIN_NMI, NEW]);
    expect(await screen.findByText(WIN_NMI.name)).toBeTruthy();
    expect(screen.getByText(NEW.name)).toBeTruthy();
    // NEGATIVE CONTROL. The needs_more_info from outside the window does not
    // put the group there.
    expect(screen.queryByText(OLD_NMI.name)).toBeNull();
  });
});

describe('the row pill shows the window verdict', () => {
  it('says "inherited" with the age of the verdict when no run is in the window', async () => {
    mountAt('/alerts?range=24h&hide_acked=false', [INH_FP]);
    const r = await row(INH_FP);
    expect(r.textContent).toContain('· inherited 3d ago');
    expect(within(r).getByTitle(/No investigation of this detection ran in this window/)).toBeTruthy();
  });

  it('does not say "inherited" for a verdict from a run in the window', async () => {
    // NEGATIVE CONTROL. The run of the window investigated another alert of
    // the group. An older server called that verdict inherited.
    const cross = group('cross', {
      inherited: true,
      inheritedReason: 'Inherited from the same detection, investigated 1d ago.',
      windowVerdict: 'false_positive',
      windowConf: 0.9,
      windowInvId: 'INV-cross',
      verdictCounts: { false_positive: 1 },
    });
    mountAt('/alerts?range=24h&hide_acked=false', [cross]);
    const r = await row(cross);
    expect(r.textContent).not.toContain('inherited');
  });

  it('shows the window verdict and its confidence, once', async () => {
    mountAt('/alerts?range=24h&hide_acked=false', [WIN_TP]);
    const r = await row(WIN_TP);
    expect(within(r).getByText('True positive')).toBeTruthy();
    expect(within(r).getByText('0.62')).toBeTruthy();
    const mix = within(r).getByTestId('verdict-mix');
    expect(mix.textContent).toBe('1 true positive, 2 false positives');
    expect(within(mix).queryByRole('button')).toBeNull();
  });

  it('names the window verdict beside a pipeline error, in window words', async () => {
    const fb = group('fb', {
      verdict: 'needs_more_info',
      fallback: true,
      windowVerdict: 'true_positive',
      windowConf: 0.62,
      windowInvId: 'INV-TP',
      verdictCounts: { true_positive: 1 },
    });
    mountAt('/alerts?range=24h&hide_acked=false', [fb]);
    const mix = within(await row(fb)).getByTestId('verdict-mix');
    const chip = within(mix).getByRole('button', { name: 'True positive 0.62' });
    expect(chip.getAttribute('title')).toBe('1 true positive in this window. Open the investigation.');
  });
});
