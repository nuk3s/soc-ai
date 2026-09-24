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
  startHuntConsole: vi.fn(),
}));

import { getHuntTemplates, startHuntConsole, type HuntTemplate } from '../lib/api';
import { ShellProvider } from '../shell/ShellContext';
import { NewHuntDrawer } from './NewHuntDrawer';

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
      expect(startHuntConsole).toHaveBeenCalledWith('hunt for lateral movement', undefined, undefined),
    );
    expect(await screen.findByText('HUNT DETAIL')).toBeTruthy();
  });

  it('fills the box from a starter and sends the starter with the hunt', async () => {
    mount();
    fireEvent.click(await screen.findByRole('button', { name: TEMPLATE.name }));
    expect((box() as HTMLTextAreaElement).value).toBe(TEMPLATE.objectiveTemplate);
    fireEvent.click(screen.getByRole('button', { name: 'Start hunt' }));
    await waitFor(() =>
      expect(startHuntConsole).toHaveBeenCalledWith(TEMPLATE.objectiveTemplate, undefined, 3),
    );
  });

  it('forgets the starter once the analyst edits the objective by hand', async () => {
    mount();
    fireEvent.click(await screen.findByRole('button', { name: TEMPLATE.name }));
    fireEvent.change(box(), { target: { value: 'my own words' } });
    fireEvent.click(screen.getByRole('button', { name: 'Start hunt' }));
    await waitFor(() =>
      expect(startHuntConsole).toHaveBeenCalledWith('my own words', undefined, undefined),
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
});
