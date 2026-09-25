import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { ProfileDimension } from '../lib/types';
import { BehaviouralProfile } from './BehaviouralProfile';

const dim = (over: Partial<ProfileDimension>): ProfileDimension => ({
  dimension: 'served_ports',
  shape: 'categorical',
  coverage: 'measured',
  support_days: 12,
  window_days: 30,
  summary: '8 members · 445, 135, 88, 5986, 389, 5985, 53, 636',
  top: [['445', 900]],
  ...over,
});

const mount = (profile: ProfileDimension[]) =>
  render(
    <MemoryRouter>
      <BehaviouralProfile profile={profile} />
    </MemoryRouter>,
  );

describe('BehaviouralProfile', () => {
  it('renders each dimension with its coverage and support', () => {
    mount([dim({}), dim({ dimension: 'connection_rate', shape: 'numeric', summary: 'work 42/h · off 3/h · weekend —' })]);
    expect(screen.getByText('served ports')).toBeTruthy();
    expect(screen.getByText('connection rate')).toBeTruthy();
    expect(screen.getAllByTestId('profile-coverage-measured')).toHaveLength(2);
    expect(screen.getAllByText(/· 12d/)).toHaveLength(2);
  });

  it('renders blind as blind, never as an empty measurement', () => {
    // The distinction the panel exists for: a host that ships no process
    // telemetry has no unusual processes in exactly the way a quiet host does.
    mount([dim({ dimension: 'process_names', coverage: 'blind', support_days: 0, summary: '', top: [] })]);
    const row = screen.getByText('processes').closest('li')!;
    expect(within(row).getByTestId('profile-coverage-blind')).toBeTruthy();
    expect(within(row).getByText(/cannot be measured/)).toBeTruthy();
    expect(within(row).queryByText(/nothing observed/)).toBeNull();
  });

  it('renders a measured empty set as nothing observed, which is a fact', () => {
    mount([dim({ summary: '', top: [] })]);
    expect(screen.getByText('nothing observed')).toBeTruthy();
    expect(screen.getByTestId('profile-coverage-measured')).toBeTruthy();
  });

  it('renders unmeasurable with the reason the grid gave, never as nothing observed', () => {
    // The grid refused the query after every retry. That is a fact about the
    // grid's size, and "nothing observed" would turn it into a fact about the host.
    mount([
      dim({
        dimension: 'active_hours',
        shape: 'active_hours',
        coverage: 'unmeasurable',
        coverage_reason: 'Trying to create too many buckets',
        support_days: 0,
        summary: '',
        top: [],
      }),
    ]);
    const row = screen.getByText('active hours').closest('li')!;
    expect(within(row).getByTestId('profile-coverage-unmeasurable')).toBeTruthy();
    expect(within(row).getByText(/not measured: Trying to create too many buckets/)).toBeTruthy();
    expect(within(row).queryByText(/nothing observed/)).toBeNull();
  });

  it('states absence rather than omitting the panel', () => {
    // A missing panel is indistinguishable from "this host has no unusual behaviour".
    mount([]);
    expect(screen.getByText(/No profile exists for this host/)).toBeTruthy();
  });
});
