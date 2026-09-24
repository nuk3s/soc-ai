// An alert whose document carries no `event.severity_label` at all.
//
// On the measured grid that was every alert in the 24 hour queue: 37 Elastic
// Defend endpoint alerts and 3 OpenCanary honeypot hits, none of them with the
// field. They rendered a "Low" badge, because the shared coercion turned any
// severity outside the four-value ladder into low, and a Severity=Low filter
// then matched none of them, because that filter is a term query on the field
// they do not have. The screen showed a value its own filter disagreed with,
// and it showed the highest-signal alerts on the range at the lowest severity
// the product has.
//
// What is pinned here: the badge says the severity is unknown, the filter can
// select exactly those rows, a ?sev=unknown deep link survives the allow-list,
// and a labelled row is untouched by all three.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ShellProvider } from '../shell/ShellContext';

const UNLABELLED = vi.hoisted(() => ({
  id: 'g-endpoint',
  name: 'Ingress Tool Transfer via CURL',
  kind: 'suricata',
  sev: 'unknown',
  count: 20,
  verdict: 'untriaged',
  conf: null,
  latest: '14m ago',
  inherited: false,
  events: [],
}));

const LABELLED = vi.hoisted(() => ({
  id: 'g-suricata',
  name: 'ET SCAN Suspicious Probe',
  kind: 'suricata',
  sev: 'low',
  count: 4,
  verdict: 'untriaged',
  conf: null,
  latest: '9m ago',
  inherited: false,
  events: [],
}));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue({ groups: [UNLABELLED, LABELLED], truncated: false, other_docs: 0 }),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
}));

import { Alerts } from './Alerts';

const mount = (url = '/alerts') =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <ShellProvider>
        <Alerts />
      </ShellProvider>
    </MemoryRouter>,
  );

/** Tick one option in the Severity MultiSelect. */
async function pickSeverity(label: string): Promise<void> {
  // The table's own "Severity" column header carries the same text, so the
  // filter trigger is picked by role.
  fireEvent.click(await screen.findByRole('button', { name: /^Severity/ }));
  fireEvent.click(await screen.findByLabelText(label));
}

describe('an alert with no severity label', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('is not badged Low', async () => {
    mount();
    await screen.findByText(UNLABELLED.name);
    // The labelled row supplies the only legitimate "Low" on this screen.
    expect(screen.getAllByText('Low')).toHaveLength(1);
  });

  it('says its severity is unknown', async () => {
    mount();
    await screen.findByText(UNLABELLED.name);
    expect(screen.getAllByText('Unknown').length).toBeGreaterThan(0);
  });

  it('is selectable by the Severity filter that describes it', async () => {
    mount();
    await screen.findByText(UNLABELLED.name);
    await pickSeverity('Unknown');
    await waitFor(() => expect(screen.queryByText(LABELLED.name)).toBeNull());
    expect(screen.getByText(UNLABELLED.name)).toBeTruthy();
  });

  it('is not selected by the Low filter it used to be badged with', async () => {
    mount();
    await screen.findByText(UNLABELLED.name);
    await pickSeverity('Low');
    await waitFor(() => expect(screen.queryByText(UNLABELLED.name)).toBeNull());
    expect(screen.getByText(LABELLED.name)).toBeTruthy();
  });

  it('survives a ?sev=unknown deep link', async () => {
    mount('/alerts?sev=unknown');
    expect(await screen.findByText('Severity · 1')).toBeTruthy();
  });
});

describe('a labelled alert is unchanged', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('still renders its own badge', async () => {
    mount();
    expect(await screen.findByText('Low')).toBeTruthy();
  });

  it('still seeds and applies the four ladder filters', async () => {
    mount('/alerts?sev=critical,high,medium,low');
    expect(await screen.findByText('Severity · 4')).toBeTruthy();
    // The labelled row is in the band, the unlabelled one is not.
    expect(screen.getByText(LABELLED.name)).toBeTruthy();
    expect(screen.queryByText(UNLABELLED.name)).toBeNull();
  });
});
