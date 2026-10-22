// The entity page tour: every anchor it names is on the page of a user
// account that no machine holds. A renamed or removed `data-tour` attribute
// fails here.
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { EntityDetail } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getEntity: vi.fn(),
  resolveMachine: vi.fn(),
  getObservations: vi.fn(),
  getLeads: vi.fn(),
}));

import { ApiError, getEntity, getLeads, getObservations, resolveMachine } from '../lib/api';
import { ENTITY_TOUR } from '../tours/content';
import { missingAnchors } from '../tours/testing';
import { Entity } from './Entity';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();

const ENTITY: EntityDetail = {
  value: 'alice',
  kind: 'unknown',
  type: 'user',
  host_key: null,
  first_seen: ago(5 * DAY),
  last_seen: ago(2 * HOUR),
  timeline: [
    {
      ts: ago(2 * HOUR),
      kind: 'investigation',
      title: 'Logon by alice from 203.0.113.7',
      verdict: 'needs_more_info',
      confidence: 0.6,
      link: '/investigation/01J0000000000000000000000',
    },
    {
      ts: ago(3 * DAY),
      kind: 'hunt_finding',
      title: 'alice logged on at an unusual hour',
      severity: 'medium',
      link: '/hunts/01J0000000000000000000001',
    },
  ],
  summary: {
    investigationCount: 1,
    huntFindingCount: 1,
    latestVerdict: 'needs_more_info',
    truePositiveCount: 0,
    leadCount: 0,
    openLeadCount: 0,
    observationCount: 0,
  },
};

beforeEach(() => {
  vi.mocked(getEntity).mockReset().mockResolvedValue(ENTITY);
  vi.mocked(getObservations).mockReset().mockResolvedValue({ entity: 'alice', days: 7, observations: [] });
  vi.mocked(getLeads).mockReset().mockResolvedValue([]);
  // An account belongs to no machine.
  vi.mocked(resolveMachine)
    .mockReset()
    .mockRejectedValue(new ApiError('No machine holds this value.', 404, 'no_host'));
});

describe('the entity page tour', () => {
  it('finds every anchor it names on the page', async () => {
    render(
      <MemoryRouter initialEntries={['/entity/alice']}>
        <Routes>
          <Route path="/entity/:value" element={<Entity />} />
        </Routes>
      </MemoryRouter>,
    );
    await screen.findByTestId('entity-header');
    await screen.findByText('Logon by alice from 203.0.113.7');

    expect(missingAnchors(ENTITY_TOUR)).toEqual([]);
  });
});
