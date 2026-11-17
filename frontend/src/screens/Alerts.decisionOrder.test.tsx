// J1 (prod review 2026-11-12, ui-core 8). The Alerts list sorted by rule
// severity, so a High false positive sat above a Medium true positive of 306
// events. "Needs decision" held one needs-more-info group and left out nine
// true positives with a waiting Escalate. A row showed a verdict chip and no
// reason. The sort line read "Sort sev ↓", an internal key that looked like a
// control and was not one.
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { ShellProvider } from '../shell/ShellContext';
import type { AlertGroup } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn(),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
}));

import { getAlerts } from '../lib/api';
import { queueOf } from '../test/alertQueue';
import { Alerts } from './Alerts';

const MIN = 60_000;
const at = (minutesAgo: number) => new Date(Date.now() - minutesAgo * MIN).toISOString();

const group = (id: string, o: Partial<AlertGroup>): AlertGroup => ({
  id,
  name: `Rule ${id}`,
  kind: 'suricata',
  sev: 'medium',
  count: 3,
  verdict: 'untriaged',
  conf: null,
  latest: '5m',
  latestTs: at(5),
  inherited: false,
  events: [],
  windowVerdict: null,
  ...o,
});

/** A group whose window run reached `verdict`. */
const judged = (id: string, verdict: AlertGroup['verdict'], o: Partial<AlertGroup> = {}): AlertGroup =>
  group(id, {
    verdict,
    conf: 0.8,
    invId: `INV-${id}`,
    windowVerdict: verdict,
    windowConf: 0.8,
    windowInvId: `INV-${id}`,
    ...o,
  });

const mountAt = (path: string, groups: AlertGroup[]) => {
  vi.mocked(getAlerts).mockResolvedValue(queueOf(groups));
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ShellProvider>
        <Alerts />
      </ShellProvider>
    </MemoryRouter>,
  );
};

const order = () => screen.getAllByTestId('alert-name').map((el) => el.textContent);
const rowOf = async (name: string) =>
  (await screen.findByText(name)).closest('[data-group-key]') as HTMLElement;

describe('the default order of the Alerts list', () => {
  it('puts the verdict first, then the severity, then the newest', async () => {
    mountAt('/alerts?range=24h&hide_acked=false', [
      judged('fp-high', 'false_positive', { sev: 'high', count: 430 }),
      judged('inc', 'inconclusive'),
      group('new', {}),
      judged('nmi', 'needs_more_info'),
      judged('tp-old', 'true_positive', { latestTs: at(90) }),
      judged('tp-low', 'true_positive', { sev: 'low' }),
      judged('tp-new', 'true_positive', { latestTs: at(1), count: 306 }),
    ]);
    await screen.findByText('Rule tp-new');
    expect(order()).toEqual([
      'Rule tp-new',
      'Rule tp-old',
      'Rule tp-low',
      'Rule nmi',
      'Rule new',
      'Rule inc',
      'Rule fp-high',
    ]);
  });

  it('keeps the sort control: Severity orders by severity', async () => {
    // NEGATIVE CONTROL. The new default must not lock the order.
    mountAt('/alerts?range=24h&hide_acked=false', [
      judged('tp', 'true_positive', { sev: 'medium' }),
      judged('fp', 'false_positive', { sev: 'high' }),
    ]);
    await screen.findByText('Rule tp');
    const menu = screen.getByLabelText('Sort') as HTMLSelectElement;
    expect(menu.value).toBe('verdict');
    expect(Array.from(menu.options).map((o) => o.textContent)).toEqual([
      'Verdict',
      'Severity',
      'Last seen',
      'Count',
      'Confidence',
      'Detection',
    ]);
    expect(order()).toEqual(['Rule tp', 'Rule fp']);
    fireEvent.change(menu, { target: { value: 'sev' } });
    expect(order()).toEqual(['Rule fp', 'Rule tp']);
    // The direction is a control too.
    fireEvent.click(screen.getByTestId('alerts-sort-dir'));
    expect(order()).toEqual(['Rule tp', 'Rule fp']);
  });

  it('honours an explicit sort in the link', async () => {
    mountAt('/alerts?range=24h&hide_acked=false&sort=sev:desc', [
      judged('tp', 'true_positive', { sev: 'medium' }),
      judged('fp', 'false_positive', { sev: 'high' }),
    ]);
    await screen.findByText('Rule tp');
    expect(order()).toEqual(['Rule fp', 'Rule tp']);
    expect((screen.getByLabelText('Sort') as HTMLSelectElement).value).toBe('sev');
  });
});

describe('Needs decision', () => {
  it('holds a true positive with a waiting action', async () => {
    mountAt('/alerts?range=24h&hide_acked=false&view=decision', [
      judged('tp-waits', 'true_positive', { waitingActions: 1 }),
      judged('tp-done', 'true_positive', { waitingActions: 0 }),
      judged('fp', 'false_positive'),
      judged('nmi', 'needs_more_info'),
    ]);
    expect(await screen.findByText('Rule tp-waits')).toBeTruthy();
    expect(screen.getByText('Rule nmi')).toBeTruthy();
    // NEGATIVE CONTROL. A true positive with no waiting action and a false
    // positive stay out.
    expect(screen.queryByText('Rule tp-done')).toBeNull();
    expect(screen.queryByText('Rule fp')).toBeNull();
    expect(screen.getByRole('button', { name: /Needs decision/ }).textContent).toContain('2');
  });
});

describe('the reason line of a row', () => {
  it('states the headline of the run behind the verdict', async () => {
    mountAt('/alerts?range=24h&hide_acked=false', [
      judged('tp', 'true_positive', {
        // The standing run is a later false positive. The row counts under
        // the true positive of the window, and states its headline.
        verdict: 'false_positive',
        invId: 'INV-fp-later',
        headline: 'The scanner is an approved asset.',
        windowHeadline: 'The request body holds a web shell upload.',
      }),
      judged('fp', 'false_positive', { headline: 'The traffic is a known updater.', windowHeadline: 'The traffic is a known updater.' }),
      group('new', { headline: null }),
    ]);
    const tp = await rowOf('Rule tp');
    const reason = within(tp).getByTestId('alert-reason');
    expect(reason.textContent).toBe('The request body holds a web shell upload.');
    // The whole sentence shows and wraps: no clip (owner, 2026-10-07).
    expect(reason.className).not.toMatch(/max-h-|overflow-hidden/);
    expect(within(await rowOf('Rule fp')).getByTestId('alert-reason').textContent).toBe(
      'The traffic is a known updater.',
    );
    // NEGATIVE CONTROL. An untriaged group has no reason, and no empty line.
    expect(within(await rowOf('Rule new')).queryByTestId('alert-reason')).toBeNull();
  });

  it('marks a true positive row with a shape, and a false positive row without one', async () => {
    mountAt('/alerts?range=24h&hide_acked=false', [
      judged('tp', 'true_positive'),
      judged('fp', 'false_positive'),
    ]);
    const tp = await rowOf('Rule tp');
    expect(within(tp).getByTestId('threat-mark').getAttribute('aria-label')).toBe('True positive');
    expect(tp.querySelector('[data-threat="true"]')).not.toBeNull();
    // NEGATIVE CONTROL. The false positive row carries no mark.
    const fp = await rowOf('Rule fp');
    expect(within(fp).queryByTestId('threat-mark')).toBeNull();
    expect(fp.querySelector('[data-threat]')).toBeNull();
  });
});
