// Wave 2 Task 7 — detection tuning stays reachable from alert context.
//
// The Operate hub (Task 6) now owns Detection Tuning as a Config panel, but
// noise NOMINATIONS still start on THIS screen: an analyst staring at a group
// that fires constantly needs a way to the tuning panel without hunting
// through the nav first. This file pins the regression the Operate-group move
// must not cause — detection tuning going unreachable from the place noise
// actually gets noticed — and that the link is a per-GROUP affordance, not
// one that multiplies across a group's expanded events.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ShellProvider } from '../shell/ShellContext';

const { GROUP_A, GROUP_B, navigate } = vi.hoisted(() => ({
  navigate: vi.fn(),
  GROUP_A: {
    id: 'g1',
    name: 'ET SCAN Test Detection A',
    kind: 'suricata',
    sev: 'high',
    count: 3,
    verdict: 'untriaged',
    conf: null,
    latest: '2m ago',
    inherited: false,
    events: [],
  },
  GROUP_B: {
    id: 'g2',
    name: 'ET SCAN Test Detection B',
    kind: 'suricata',
    sev: 'medium',
    count: 1,
    verdict: 'untriaged',
    conf: null,
    latest: '5m ago',
    inherited: false,
    events: [],
  },
}));

vi.mock('react-router-dom', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-router-dom')>()),
  useNavigate: () => navigate,
}));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue([GROUP_A, GROUP_B]),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
  getAlertGroupEvents: vi.fn().mockResolvedValue([
    { id: 'ev1', src: '—', dst: '—', host: '—', sev: 'high', ts: '2026-08-18T00:00:00Z', ago: '2m' },
    { id: 'ev2', src: '—', dst: '—', host: '—', sev: 'high', ts: '2026-08-18T00:01:00Z', ago: '1m' },
  ]),
}));

import { Alerts } from './Alerts';

function mount() {
  return render(
    <MemoryRouter initialEntries={['/alerts']}>
      <ShellProvider>
        <Alerts />
      </ShellProvider>
    </MemoryRouter>,
  );
}

describe('Alerts — tune-rule deep-link into detection tuning', () => {
  beforeEach(() => navigate.mockClear());

  it('offers a tune-rule link on an alert group that deep-links to detection tuning', async () => {
    mount();
    await screen.findByText(GROUP_A.name);
    const [link] = screen.getAllByRole('button', { name: /tune rule/i });
    fireEvent.click(link);
    // configLayout.ts's PANELS entry for the Detection tuning panel — the id
    // Config's location.hash handler resolves to open it directly.
    expect(navigate).toHaveBeenCalledWith('/config#detection-tuning');
  });

  it('does not also toggle the group row open when the link is clicked', async () => {
    mount();
    await screen.findByText(GROUP_A.name);
    const [link] = screen.getAllByRole('button', { name: /tune rule/i });
    fireEvent.click(link);
    // Events are lazy-fetched only on expand (toggleExpand) — its absence is
    // the visible proof the row's own onClick never ran behind the link's.
    expect(screen.queryByText('Loading events…')).toBeNull();
  });

  it('renders exactly one tune-rule link per group row, not per event', async () => {
    mount();
    await screen.findByText(GROUP_A.name);
    await screen.findByText(GROUP_B.name);
    // Two collapsed groups → exactly two links, one per row.
    expect(screen.getAllByRole('button', { name: /tune rule/i })).toHaveLength(2);

    // Expand GROUP_A to load its (mocked) events — if the link were placed
    // inside the per-event map instead of the per-group row, this count
    // would grow past two once the events render.
    fireEvent.click(screen.getByText(GROUP_A.name));
    await waitFor(() => expect(screen.queryByText('Loading events…')).toBeNull());
    expect(screen.getAllByRole('button', { name: /tune rule/i })).toHaveLength(2);
  });
});
