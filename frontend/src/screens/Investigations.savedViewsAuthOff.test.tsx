// Operator 4.1 (dogfood 2026-10-06): on a deployment with authentication off,
// Alerts and Investigations showed no saved-view control and no line, so an
// analyst read saved views as a feature the product does not have. The
// toolbar now shows the control disabled, with the cause beside it.
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { InvestigationList } from '../lib/types';

const listInvestigations = vi.hoisted(() => vi.fn());
const listSavedViews = vi.hoisted(() => vi.fn());
const getMe = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations,
  listSavedViews,
  getMe,
}));

import { Investigations } from './Investigations';

const EMPTY: InvestigationList = {
  rows: [],
  total: 0,
  running: 0,
  truePositives: 0,
  totalAll: 0,
  active: false,
  limit: 50,
  offset: 0,
};

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/investigations']}>
      <Investigations />
    </MemoryRouter>,
  );

beforeEach(() => {
  listInvestigations.mockReset().mockResolvedValue(EMPTY);
  listSavedViews.mockReset().mockResolvedValue([]);
  getMe.mockReset();
});

describe('saved views on a deployment with authentication off', () => {
  it('shows the disabled control and the reason', async () => {
    getMe.mockResolvedValue({ username: 'anonymous', role: 'admin', status: '', signed_in: false });
    mount();
    expect(
      await screen.findByText(
        'Saved views need a signed-in session. This deployment has authentication off.',
      ),
    ).toBeTruthy();
    const save = screen.getByRole('button', { name: /Save view/ }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    expect(listSavedViews).not.toHaveBeenCalled();
  });

  it('NEGATIVE CONTROL: a signed-in session shows the working Save control', async () => {
    getMe.mockResolvedValue({ username: 'analyst', role: 'analyst', status: '', signed_in: true });
    mount();
    await waitFor(() => expect(listSavedViews).toHaveBeenCalledWith('investigations'));
    const save = (await screen.findByRole('button', { name: /Save view/ })) as HTMLButtonElement;
    expect(save.disabled).toBe(false);
    expect(screen.queryByText(/authentication off/)).toBeNull();
  });
});
