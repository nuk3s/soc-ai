// One name per page, for the breadcrumb, the sidebar and a back link. The nav
// said "Config" over a page the guide called "Settings", "Operate" named the
// group and its first page, and the lead, status and entity pages had no
// breadcrumb (dogfood 2026-10-06). A back link names the page the analyst
// came from: the investigation page said "Back to Alerts" to an analyst who
// came from Investigations.
import { act, render, screen } from '@testing-library/react';
import { MemoryRouter, useNavigate } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { crumbFor, pageLabel } from './pages';
import { PreviousPageTracker } from './PreviousPageTracker';
import { ShortcutSheet } from './ShortcutSheet';
import { ShellProvider, useShell } from './ShellContext';

describe('crumbFor', () => {
  it.each([
    ['/leads/18', 'Hunts', 'Lead 18'],
    ['/operate', 'Status', undefined],
    ['/config', 'Settings', undefined],
    ['/entity/198.51.100.7', 'Hosts', '198.51.100.7'],
    ['/hunts/01HUNT', 'Hunts', '01HUNT'],
    ['/investigation/01INV', 'Investigation', '01INV'],
    ['/dashboard', 'Dashboard', undefined],
  ])('names %s', (path, crumb, crumb2) => {
    expect(crumbFor(path)).toEqual(crumb2 ? { crumb, crumb2 } : { crumb });
  });

  it('decodes the record it names', () => {
    expect(crumbFor('/hosts/agent%3A7f3a').crumb2).toBe('agent:7f3a');
  });

  // NEGATIVE CONTROL. An unknown path has no breadcrumb.
  it('names nothing for a path that is no page', () => {
    expect(crumbFor('/no-such-page')).toEqual({ crumb: '' });
  });
});

describe('pageLabel', () => {
  it('names the page a back link returns to', () => {
    expect(pageLabel('/investigations?range=7d')).toBe('Investigations');
    expect(pageLabel('/alerts')).toBe('Alerts');
    expect(pageLabel('/hunts/01HUNT')).toBe('Hunt');
    expect(pageLabel('/leads/18')).toBe('Lead 18');
    expect(pageLabel('/hosts/10.0.0.4')).toBe('Host');
  });
});

function Probe() {
  const { previousPage } = useShell();
  const navigate = useNavigate();
  return (
    <>
      <div data-testid="previous">{previousPage ? `${previousPage.label}|${previousPage.path}` : 'none'}</div>
      <button onClick={() => navigate('/investigations?range=7d')}>to list</button>
      <button onClick={() => navigate('/investigations?range=30d')}>widen</button>
      <button onClick={() => navigate('/investigation/01INV')}>to run</button>
    </>
  );
}

describe('previousPage', () => {
  it('holds the page the analyst left, with its search', () => {
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <ShellProvider>
          <PreviousPageTracker />
          <Probe />
        </ShellProvider>
      </MemoryRouter>,
    );
    // The first page of a visit has no page before it.
    expect(screen.getByTestId('previous').textContent).toBe('none');
    act(() => screen.getByText('to list').click());
    expect(screen.getByTestId('previous').textContent).toBe('Dashboard|/dashboard');
    // A change of search on one page is not a change of page.
    act(() => screen.getByText('widen').click());
    expect(screen.getByTestId('previous').textContent).toBe('Dashboard|/dashboard');
    act(() => screen.getByText('to run').click());
    expect(screen.getByTestId('previous').textContent).toBe('Investigations|/investigations?range=30d');
  });
});

function OpenSheet() {
  const { openShortcuts } = useShell();
  return <button onClick={openShortcuts}>open sheet</button>;
}

describe('ShortcutSheet', () => {
  it('opens from the shell and closes on its own button', () => {
    render(
      <MemoryRouter>
        <ShellProvider>
          <OpenSheet />
          <ShortcutSheet />
        </ShellProvider>
      </MemoryRouter>,
    );
    expect(screen.queryByRole('dialog', { name: 'Keyboard shortcuts' })).toBeNull();
    act(() => screen.getByText('open sheet').click());
    expect(screen.getByRole('dialog', { name: 'Keyboard shortcuts' })).toBeTruthy();
    act(() => screen.getByRole('button', { name: 'Close' }).click());
    expect(screen.queryByRole('dialog', { name: 'Keyboard shortcuts' })).toBeNull();
  });
});
