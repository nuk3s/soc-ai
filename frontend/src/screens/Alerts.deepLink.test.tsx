// The Dashboard's Untriaged tile lands here. It counts alert GROUPS over the
// operator's chosen range with acked groups included; Alerts defaults to
// range=24h with hide_acked ON. Unless the link's params actually seed the
// screen's state, a 7d dashboard — or a fully-acked untriaged group — arrives
// at a list that structurally cannot contain the row it just counted (prod
// 2026-08-07: 46 groups vs 37, 13,053 events vs 9,930 across that default).
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ShellProvider } from '../shell/ShellContext';

const GROUP = vi.hoisted(() => ({
  id: 'g1',
  name: 'ET SCAN Test Detection',
  kind: 'suricata',
  sev: 'high',
  count: 3,
  verdict: 'untriaged',
  conf: null,
  latest: '2m ago',
  inherited: false,
  events: [],
}));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue([GROUP]),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
}));

import { Alerts } from './Alerts';
import { alertsHref } from '../components/HostKpis';
import { getAlerts } from '../lib/api';

const mount = (url: string) =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <ShellProvider>
        <Alerts />
      </ShellProvider>
    </MemoryRouter>,
  );

/** Last query the screen actually sent to GET /alerts. */
const lastQuery = () => {
  const calls = vi.mocked(getAlerts).mock.calls;
  return calls[calls.length - 1][0];
};

describe('Alerts deep-link seeding', () => {
  beforeEach(() => {
    vi.mocked(getAlerts).mockClear();
  });

  it('still seeds the Severity filter from ?sev=', async () => {
    mount('/alerts?sev=critical,high,bogus');
    expect(await screen.findByText('Severity · 2')).toBeTruthy();
  });

  it('seeds the Verdict filter from ?verdict=', async () => {
    mount('/alerts?verdict=untriaged');
    // The MultiSelect trigger shows its active count.
    const trigger = await screen.findByText('Verdict · 1');
    fireEvent.click(trigger);
    const box = screen.getByLabelText('Untriaged') as HTMLInputElement;
    expect(box.checked).toBe(true);
  });

  it('accepts several verdicts and drops unknown ones', async () => {
    mount('/alerts?verdict=untriaged,inconclusive,bogus');
    expect(await screen.findByText('Verdict · 2')).toBeTruthy();
  });

  it('leaves the Verdict filter open when the param is absent', async () => {
    mount('/alerts');
    expect(await screen.findByText('Verdict')).toBeTruthy();
  });

  it('seeds the time range from ?range= so the Dashboard window survives', async () => {
    mount('/alerts?range=7d');
    await screen.findByText(GROUP.name);
    expect(lastQuery()).toMatchObject({ range: '7d' });
  });

  it('ignores an unknown ?range= rather than querying a bogus window', async () => {
    mount('/alerts?range=nonsense');
    await screen.findByText(GROUP.name);
    expect(lastQuery()).toMatchObject({ range: '24h' });
  });

  it('carries a custom range through with its from/to', async () => {
    mount('/alerts?range=custom&from=2026-08-01T00:00&to=2026-08-02T00:00');
    await screen.findByText(GROUP.name);
    expect(lastQuery()).toMatchObject({
      range: 'custom',
      from: '2026-08-01T00:00',
      to: '2026-08-02T00:00',
    });
  });

  it('turns off "Hide acknowledged" on ?hide_acked=false', async () => {
    mount('/alerts?hide_acked=false');
    await screen.findByText(GROUP.name);
    expect(lastQuery()!.hideAcked).toBeFalsy();
  });

  it('keeps "Hide acknowledged" on by default', async () => {
    mount('/alerts');
    await screen.findByText(GROUP.name);
    expect(lastQuery()).toMatchObject({ hideAcked: true });
  });

  it('lands the whole Dashboard untriaged link on a list that can hold the group', async () => {
    mount('/alerts?verdict=untriaged&range=7d&hide_acked=false');
    const row = await screen.findByText(GROUP.name);
    expect(row).toBeTruthy();
    expect(lastQuery()).toMatchObject({ range: '7d' });
    expect(lastQuery()!.hideAcked).toBeFalsy();
    fireEvent.click(screen.getByText('Verdict · 1'));
    expect((screen.getByLabelText('Untriaged') as HTMLInputElement).checked).toBe(true);
  });

  it('lands the host page\'s Alerts KPI on a list scoped to the host it counted', async () => {
    // The host page's Alerts tile is a fixed 7-day raw grid count with no ack
    // join, scoped to one host. All three params have to be honoured, or a
    // host whose only detections are older than a day, or acked — or a QUIET
    // host on a noisy network — lands on a list that cannot hold (or drowns)
    // the rows just counted.
    mount(alertsHref('192.0.2.10'));
    await screen.findByText(GROUP.name);
    expect(lastQuery()).toMatchObject({
      range: '7d',
      q: '(source.ip:192.0.2.10 OR destination.ip:192.0.2.10)',
    });
    expect(lastQuery()!.hideAcked).toBeFalsy();
  });

  it('shows the deep-linked OQL filter as a chip, so the narrowing is visible', async () => {
    // A list silently narrowed by an invisible filter reads as the whole
    // network having only these detections.
    mount(alertsHref('192.0.2.10'));
    const chip = await screen.findByTestId('alerts-q-chip');
    expect(chip.textContent).toContain('(source.ip:192.0.2.10 OR destination.ip:192.0.2.10)');
  });

  it('clears the filter from its chip and re-fetches the whole feed', async () => {
    mount(alertsHref('192.0.2.10'));
    const chip = await screen.findByTestId('alerts-q-chip');
    fireEvent.click(within(chip).getByRole('button', { name: /clear the alert filter/i }));
    await screen.findByText(GROUP.name);
    expect(screen.queryByTestId('alerts-q-chip')).toBeNull();
    expect(lastQuery()!.q).toBeUndefined();
  });

  it('ignores a blank ?q= rather than sending whitespace to the parser', async () => {
    mount('/alerts?q=%20%20');
    await screen.findByText(GROUP.name);
    expect(lastQuery()!.q).toBeUndefined();
    expect(screen.queryByTestId('alerts-q-chip')).toBeNull();
  });
});

describe('Alerts verdict filter actually filters', () => {
  it('hides a group whose verdict is not selected', async () => {
    mount('/alerts?verdict=true_positive');
    // The header summary counts the FETCHED groups, so it proves the data
    // landed before we assert the row was filtered out (rather than never
    // arriving).
    await screen.findByText(/1 untriaged · 1 detection ·/);
    expect(screen.queryByText(GROUP.name)).toBeNull();
  });
});
