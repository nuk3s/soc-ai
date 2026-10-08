// A hunt row on the bell and on the Notifications screen reads its `outcome`
// field. The bell said "Hunt finished: no threat observed" for 8 analytic runs
// that could not reach their data source (dogfood 2026-10-06). The server now
// names the outcome, and the console paints a chip from the field, never from
// the title text.
import { act, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getNotifications: vi.fn(),
  getWorkspaces: vi.fn().mockResolvedValue([]),
  getHealth: vi.fn().mockResolvedValue({ es: { ok: true, detail: 'ok' }, llm: { ok: true, detail: 'ok' } }),
  getNeedsYouCount: vi.fn().mockRejectedValue(new Error('not in this test')),
}));

import { getNotifications } from '../lib/api';
import { huntOutcomeChip } from '../lib/notifications';
import type { Notification } from '../lib/types';
import { ShellProvider } from '../shell/ShellContext';
import { Topbar } from '../shell/Topbar';
import { Notifications } from './Notifications';

const ROWS: Notification[] = [
  {
    id: 'hunt-done:H1',
    tone: 'warn',
    title:
      'Analytic could not run: Service ticket from a workstation. The data source did not accept a connection.',
    when: '2h',
    href: '/hunts/H1',
    outcome: 'could_not_run',
  },
  {
    id: 'hunt-done:H2',
    tone: 'danger',
    title: 'Hunt finished, 1 threat finding: find beacons',
    when: '3h',
    href: '/hunts/H2',
    outcome: 'threat_found',
  },
  {
    id: 'inv-done:I1',
    tone: 'accent',
    title: 'Verdict false_positive: ET INFO X',
    when: '4h',
    href: '/investigation/I1',
  },
];

const rowOf = (text: RegExp) => screen.getByText(text).closest('[data-testid="notification-row"]') as HTMLElement;

beforeEach(() => {
  localStorage.clear();
  vi.mocked(getNotifications).mockResolvedValue(ROWS);
});

describe('Notifications screen paints a hunt by its outcome', () => {
  it('marks an analytic that could not run, in the warn tone', async () => {
    render(
      <MemoryRouter>
        <Notifications />
      </MemoryRouter>,
    );
    await screen.findByText(/Analytic could not run/);
    const row = rowOf(/Analytic could not run/);
    expect(within(row).getByTestId('hunt-outcome').textContent).toBe('Could not run');
    expect(within(row).getByTestId('notification-tone').getAttribute('title')).toMatch(/attention/i);
    expect(within(rowOf(/1 threat finding/)).getByTestId('hunt-outcome').textContent).toBe('Threat found');
  });

  // NEGATIVE CONTROL. A row with no outcome is not a hunt, and gets no chip.
  it('gives an investigation row no outcome chip', async () => {
    render(
      <MemoryRouter>
        <Notifications />
      </MemoryRouter>,
    );
    await screen.findByText(/ET INFO X/);
    expect(within(rowOf(/ET INFO X/)).queryByTestId('hunt-outcome')).toBeNull();
  });
});

describe('the bell paints a hunt by its outcome', () => {
  it('shows the outcome chip on the bell row', async () => {
    render(
      <MemoryRouter>
        <ShellProvider>
          <Topbar />
        </ShellProvider>
      </MemoryRouter>,
    );
    const bell = await screen.findByRole('button', { name: /^Notifications/ });
    await act(async () => {
      await Promise.resolve();
    });
    act(() => bell.click());
    const title = await screen.findByText(/Analytic could not run/);
    const row = title.closest('[class*="border-b"]') as HTMLElement;
    expect(within(row).getByTestId('hunt-outcome').textContent).toBe('Could not run');
  });
});

describe('huntOutcomeChip', () => {
  it('names each outcome with the shared labels', () => {
    expect(huntOutcomeChip('threat_found')?.label).toBe('Threat found');
    expect(huntOutcomeChip('no_threat')?.label).toBe('No threat found');
    expect(huntOutcomeChip('no_threat_gap')?.label).toBe('No threat found, visibility gap');
    expect(huntOutcomeChip('no_answer')?.label).toBe('No answer');
    expect(huntOutcomeChip('could_not_run')?.label).toBe('Could not run');
    expect(huntOutcomeChip('running')?.label).toBe('Running');
    expect(huntOutcomeChip(undefined)).toBeNull();
    // A failed run is grey, never green (lib/labels.ts).
    expect(huntOutcomeChip('could_not_run')?.color).toBe('#8b949e');
  });

  // An outcome a newer server adds must not read as a clean result.
  it('reads an unknown outcome in its own words, in amber', () => {
    expect(huntOutcomeChip('something_new')).toEqual({ label: 'Something new', color: '#f5a623' });
  });
});
