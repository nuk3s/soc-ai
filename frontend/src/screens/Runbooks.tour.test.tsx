// The Runbooks page tour points at real elements (tours/content.ts).
//
// The page renders with one runbook that carries a linked rule and a tag.
// Every anchor the tour names must then be on the page, so a renamed or
// removed `data-tour` attribute fails here.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getRunbooks: vi.fn().mockResolvedValue([
    {
      id: 7,
      title: 'Beaconing triage',
      content: '# Beaconing triage\n\nCompare the interval with the baseline of the host.',
      tags: ['beaconing'],
      linked_rules: ['ET MALWARE Example beacon'],
      draft: false,
      created_by: 'analyst',
      created_at: new Date(Date.now() - 86_400_000).toISOString(),
      updated_at: new Date(Date.now() - 3_600_000).toISOString(),
      embedded: null,
      stale: null,
    },
  ]),
}));

import { RUNBOOKS_TOUR } from '../tours/content';
import { missingAnchors } from '../tours/testing';
import { Runbooks } from './Runbooks';

describe('the Runbooks page tour', () => {
  it('finds every anchor it names', async () => {
    render(
      <MemoryRouter initialEntries={['/runbooks']}>
        <Runbooks />
      </MemoryRouter>,
    );
    await screen.findByText('Beaconing triage');
    await screen.findByRole('link', { name: 'Alerts of the linked rule ET MALWARE Example beacon' });

    expect(missingAnchors(RUNBOOKS_TOUR)).toEqual([]);
  });
});
