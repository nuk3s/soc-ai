// The detection-kind badge on an alert group row.
//
// 'alert' is the feed's generic kind: what `_kind_for` returns for an
// alert-labelled document whose `event.dataset` is not one of the three it
// maps. On the measured grid that was 37 of the 40 alerts in the 24 hour
// queue, all of them Elastic Defend endpoint alerts, and every one of them
// wore a SURICATA badge because the value was coerced to a detector the SPA
// happened to know. No Suricata sensor produced them and they carry no network
// flow at all, so the badge named the wrong tool and implied the wrong shape of
// evidence.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ShellProvider } from '../shell/ShellContext';

const ENDPOINT = vi.hoisted(() => ({
  id: 'g-endpoint',
  name: 'Ingress Tool Transfer via CURL',
  kind: 'alert',
  sev: 'unknown',
  count: 20,
  verdict: 'untriaged',
  conf: null,
  latest: '14m ago',
  inherited: false,
  events: [],
}));

const SURICATA = vi.hoisted(() => ({
  id: 'g-suricata',
  name: 'ET SCAN Suspicious Probe',
  kind: 'suricata',
  sev: 'high',
  count: 4,
  verdict: 'untriaged',
  conf: null,
  latest: '9m ago',
  inherited: false,
  events: [],
}));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue({ groups: [ENDPOINT, SURICATA], truncated: false, other_docs: 0 }),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
}));

import { Alerts } from './Alerts';

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/alerts']}>
      <ShellProvider>
        <Alerts />
      </ShellProvider>
    </MemoryRouter>,
  );

describe('the detection-kind badge', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('does not call a generic alert a Suricata hit', async () => {
    mount();
    await screen.findByText(ENDPOINT.name);
    // The one genuine Suricata group supplies the only legitimate badge.
    expect(screen.getAllByText('suricata')).toHaveLength(1);
  });

  it('names the generic kind for what it is', async () => {
    mount();
    await screen.findByText(ENDPOINT.name);
    expect(screen.getByText('alert')).toBeTruthy();
  });

  it('leaves a real detector kind alone', async () => {
    mount();
    expect(await screen.findByText('suricata')).toBeTruthy();
  });
});
