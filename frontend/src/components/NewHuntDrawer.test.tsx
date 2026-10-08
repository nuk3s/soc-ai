// The composer left the page and lives in a drawer behind one button. These
// tests pin what the drawer must carry: the objective box, the starters, the
// template control and the Start hunt button, and that a starter still sends
// its template id so the server runs the starter's analytics first.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHuntTemplates: vi.fn(),
  getHuntComposer: vi.fn(),
  startHuntConsole: vi.fn(),
}));

import {
  getHuntComposer,
  getHuntTemplates,
  startHuntConsole,
  type HuntTemplate,
} from '../lib/api';
import { ShellProvider } from '../shell/ShellContext';
import { NewHuntDrawer, notApplicableReason, runTimeLine } from './NewHuntDrawer';

const TEMPLATE: HuntTemplate = {
  id: 3,
  name: 'Directory replication review',
  objectiveTemplate: 'Hunt for directory replication by a non-machine account.',
  requiredDatasets: [],
  defaultWindowMinutes: 1440,
  builtin: true,
  createdBy: 'system',
  createdAt: '2026-08-01T00:00:00+00:00',
  available: true,
  missingDatasets: [],
  applicable: true,
  missingEnvironment: [],
};

const onClose = vi.fn();

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/hunts']}>
      <ShellProvider>
        <Routes>
          <Route path="/hunts" element={<NewHuntDrawer onClose={onClose} />} />
          <Route path="/hunts/:id" element={<div>HUNT DETAIL</div>} />
        </Routes>
      </ShellProvider>
    </MemoryRouter>,
  );

const box = () => screen.getByPlaceholderText(/hunt for beaconing to rare external IPs/i);

beforeEach(() => {
  onClose.mockReset();
  vi.mocked(getHuntTemplates).mockReset().mockResolvedValue([TEMPLATE]);
  vi.mocked(startHuntConsole).mockReset().mockResolvedValue({ hunt_id: 'H7' });
  vi.mocked(getHuntComposer).mockReset().mockResolvedValue({
    max_range_days: 30,
    run_minutes_low: 5,
    run_minutes_high: 8,
    run_sample: 12,
  });
});

// W11: the dialog states the range, the cap the grid answers to, the run time
// and the reason a starter does not apply. It stated none of them.
describe('NewHuntDrawer range, cap and run time (W11)', () => {
  it('states the cap and the run time, and sends the range the analyst chose', async () => {
    mount();
    expect((await screen.findByTestId('new-hunt-range-cap')).textContent).toBe(
      'The grid answers up to 30 days back.',
    );
    expect(screen.getByTestId('new-hunt-run-time').textContent).toBe(
      'A hunt takes 5 to 8 minutes.',
    );
    const range = screen.getByLabelText('Time range') as HTMLSelectElement;
    const offered = Array.from(range.options).map((o) => o.textContent);
    expect(offered).toEqual([
      'As the objective states',
      'Last day',
      'Last 3 days',
      'Last 7 days',
      'Last 14 days',
      'Last 30 days',
    ]);
    fireEvent.change(range, { target: { value: '7' } });
    fireEvent.change(box(), { target: { value: 'hunt for beacons' } });
    fireEvent.click(screen.getByText('Start hunt'));
    await waitFor(() =>
      expect(startHuntConsole).toHaveBeenCalledWith('hunt for beacons', undefined, undefined, 7),
    );
  });

  // Negative control: too few finished hunts, and no composer answer.
  it('states no run time it cannot read, and no cap it was not sent', async () => {
    vi.mocked(getHuntComposer).mockRejectedValue(new Error('down'));
    mount();
    await screen.findByLabelText('Time range');
    expect(screen.queryByTestId('new-hunt-range-cap')).toBeNull();
    expect(screen.queryByTestId('new-hunt-run-time')).toBeNull();
    expect(runTimeLine(null, null)).toBe('');
    expect(runTimeLine(6, 6)).toBe('A hunt takes about 6 minutes.');
  });

  it('names the reason a starter does not apply, in plain view', async () => {
    vi.mocked(getHuntTemplates).mockResolvedValue([
      TEMPLATE,
      {
        ...TEMPLATE,
        id: 9,
        name: 'DCE-RPC abuse / DC attacks',
        builtin: true,
        available: false,
        missingDatasets: ['zeek.dce_rpc'],
      },
    ]);
    mount();
    fireEvent.click(await screen.findByText(/Not applicable here/));
    expect(screen.getByTestId('starter-reason-9').textContent).toBe(
      'Needs zeek.dce_rpc. This grid has none.',
    );
    expect(
      notApplicableReason({
        available: true,
        missingDatasets: [],
        applicable: false,
        missingEnvironment: ['a domain-joined host'],
      }),
    ).toBe('Needs a domain-joined host. The network shows none.');
  });

  it('offers starters that name no tool when the starter list cannot be read', async () => {
    vi.mocked(getHuntTemplates).mockRejectedValue(new Error('down'));
    mount();
    for (const label of ['Beaconing to rare IPs', 'DNS / C2 exfiltration', 'New external services', 'DCE-RPC abuse / DC attacks']) {
      fireEvent.click(await screen.findByText(label));
      expect((box() as HTMLTextAreaElement).value).not.toMatch(/\bt_[a-z_]+/);
    }
  });
});

describe('NewHuntDrawer', () => {
  // One term per thing. The heading read Starters and the copy under it read
  // "templates", so the chips had two names on one panel.
  it('carries the objective box, the starters, the add control and the button', async () => {
    mount();
    expect(await screen.findByRole('dialog')).toBeTruthy();
    expect(screen.getByText('New hunt')).toBeTruthy();
    expect(box()).toBeTruthy();
    expect(screen.getByText('Starters')).toBeTruthy();
    expect(await screen.findByRole('button', { name: TEMPLATE.name })).toBeTruthy();
    expect(screen.getByRole('button', { name: /Starter$/ })).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Template$/ })).toBeNull();
    expect(screen.getByRole('button', { name: 'Start hunt' })).toBeTruthy();
    expect(
      screen.getByText('The hunt starts at once. It appears in the hunt list as Running.'),
    ).toBeTruthy();
  });

  it('will not start a hunt with an empty objective', async () => {
    mount();
    const start = screen.getByRole('button', { name: 'Start hunt' }) as HTMLButtonElement;
    expect(start.disabled).toBe(true);
  });

  it('starts the hunt the analyst typed', async () => {
    mount();
    fireEvent.change(box(), { target: { value: 'hunt for lateral movement' } });
    fireEvent.click(screen.getByRole('button', { name: 'Start hunt' }));
    await waitFor(() =>
      expect(startHuntConsole).toHaveBeenCalledWith('hunt for lateral movement', undefined, undefined, undefined),
    );
    expect(await screen.findByText('HUNT DETAIL')).toBeTruthy();
  });

  it('fills the box from a starter and sends the starter with the hunt', async () => {
    mount();
    fireEvent.click(await screen.findByRole('button', { name: TEMPLATE.name }));
    expect((box() as HTMLTextAreaElement).value).toBe(TEMPLATE.objectiveTemplate);
    fireEvent.click(screen.getByRole('button', { name: 'Start hunt' }));
    await waitFor(() =>
      expect(startHuntConsole).toHaveBeenCalledWith(TEMPLATE.objectiveTemplate, undefined, 3, undefined),
    );
  });

  it('forgets the starter once the analyst edits the objective by hand', async () => {
    mount();
    fireEvent.click(await screen.findByRole('button', { name: TEMPLATE.name }));
    fireEvent.change(box(), { target: { value: 'my own words' } });
    fireEvent.click(screen.getByRole('button', { name: 'Start hunt' }));
    await waitFor(() =>
      expect(startHuntConsole).toHaveBeenCalledWith('my own words', undefined, undefined, undefined),
    );
  });

  it('states a refused start rather than closing on it', async () => {
    vi.mocked(startHuntConsole).mockRejectedValue(new Error('the agent is busy'));
    mount();
    fireEvent.change(box(), { target: { value: 'hunt for lateral movement' } });
    fireEvent.click(screen.getByRole('button', { name: 'Start hunt' }));
    expect(await screen.findByText('the agent is busy')).toBeTruthy();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('closes from the header button and from the keyboard', async () => {
    mount();
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(onClose).toHaveBeenCalledTimes(1);
    fireEvent.keyDown(window, { key: 'Escape' });
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(2));
  });

  // The "Run this query" link of an observation opens the drawer with the
  // query in the objective. The analyst reads it and starts the hunt.
  it('opens with the objective a link hands it', async () => {
    render(
      <MemoryRouter initialEntries={['/hunts']}>
        <ShellProvider>
          <Routes>
            <Route
              path="/hunts"
              element={
                <NewHuntDrawer onClose={onClose} initialObjective="Run this OQL query: source.ip:x" />
              }
            />
          </Routes>
        </ShellProvider>
      </MemoryRouter>,
    );
    expect((box() as HTMLTextAreaElement).value).toBe('Run this OQL query: source.ip:x');
  });

  it('opens empty with no objective handed to it', () => {
    mount();
    expect((box() as HTMLTextAreaElement).value).toBe('');
  });
});
