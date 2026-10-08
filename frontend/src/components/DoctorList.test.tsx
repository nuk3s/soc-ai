// The Diagnostics pane lists every doctor row (range dogfood 2026-10-05, D3).
//
// The Setup health card shows FAIL and WARN only. The "estate model" and the
// "prompt assets" rows are INFO and PASS, and no console surface showed them.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getPreflightDetail: vi.fn(),
  refreshPreflight: vi.fn(),
}));

import { ApiError, getPreflightDetail, refreshPreflight } from '../lib/api';
import type { PreflightDetail } from '../lib/types';
import { DoctorList, doctorCounts } from './DoctorList';

const DETAIL: PreflightDetail = {
  checked_at: new Date(Date.now() - 120_000).toISOString(),
  rows: [
    { name: 'blocklists', status: 'WARN', detail: 'no feed is loaded', hint: 'Run soc-ai blocklists refresh.' },
    { name: 'estate model', status: 'INFO', detail: 'off. The extra package that the estate model needs is installed.', hint: '' },
    { name: 'prompt assets', status: 'PASS', detail: '2 assets are present', hint: '' },
    { name: 'oracle route', status: 'PASS', detail: 'the route answers', hint: '' },
  ],
};

beforeEach(() => {
  vi.mocked(getPreflightDetail).mockReset().mockResolvedValue(DETAIL);
  vi.mocked(refreshPreflight).mockReset();
});

describe('DoctorList', () => {
  it('shows every row, the INFO and PASS rows too, with its status and detail', async () => {
    render(<DoctorList />);
    const estate = await screen.findByTestId('doctor-row-estate model');
    expect(within(estate).getByTestId('doctor-status').textContent).toBe('INFO');
    expect(estate.textContent).toContain('off. The extra package that the estate model needs is installed.');
    const assets = screen.getByTestId('doctor-row-prompt assets');
    expect(within(assets).getByTestId('doctor-status').textContent).toBe('PASS');
    expect(screen.getByTestId('doctor-row-oracle route')).toBeTruthy();
    // The WARN row the Setup health card shows is here too.
    const warn = screen.getByTestId('doctor-row-blocklists');
    expect(within(warn).getByTestId('doctor-status').textContent).toBe('WARN');
    expect(getPreflightDetail).toHaveBeenCalledTimes(1);
    expect(refreshPreflight).not.toHaveBeenCalled();
  });

  it('shows the fix line only on a row that carries one', async () => {
    render(<DoctorList />);
    const warn = await screen.findByTestId('doctor-row-blocklists');
    expect(within(warn).getByTestId('doctor-fix').textContent).toBe('Run soc-ai blocklists refresh.');
    expect(within(screen.getByTestId('doctor-row-estate model')).queryByTestId('doctor-fix')).toBeNull();
  });

  it('runs the checks again on Refresh and shows the new rows', async () => {
    vi.mocked(refreshPreflight).mockResolvedValue({
      checked_at: new Date().toISOString(),
      rows: [{ name: 'estate model', status: 'INFO', detail: 'learning. No fit is on record yet.', hint: '' }],
    });
    render(<DoctorList />);
    await screen.findByTestId('doctor-row-estate model');
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    await waitFor(() => expect(refreshPreflight).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(screen.getByTestId('doctor-row-estate model').textContent).toContain('learning.'),
    );
    expect(screen.queryByTestId('doctor-row-prompt assets')).toBeNull();
  });

  it('says the read failed and shows no row', async () => {
    vi.mocked(getPreflightDetail).mockRejectedValue(new Error('boom'));
    render(<DoctorList />);
    expect((await screen.findByTestId('doctor-failed')).textContent).toContain('The doctor read failed.');
    expect(screen.queryByTestId('doctor-status')).toBeNull();
  });

  it('names the admin rule on a 403', async () => {
    vi.mocked(getPreflightDetail).mockRejectedValue(new ApiError('forbidden', 403));
    render(<DoctorList />);
    expect((await screen.findByTestId('doctor-failed')).textContent).toBe(
      'Only an admin can read the doctor rows.',
    );
  });
});

describe('doctorCounts', () => {
  it('counts each status in a fixed order', () => {
    expect(doctorCounts(DETAIL.rows)).toBe('1 WARN · 1 INFO · 2 PASS');
  });
});

describe('DoctorList, the WARN filter', () => {
  it('shows the WARN rows only when the header chip asks', async () => {
    const seen: number[] = [];
    render(<DoctorList warnOnly onRows={(rows) => seen.push(rows.length)} />);
    expect(await screen.findByTestId('doctor-row-blocklists')).toBeTruthy();
    expect(screen.queryByTestId('doctor-row-estate model')).toBeNull();
    // The header counts every row of the read, not the filtered list.
    expect(seen).toEqual([4]);
  });

  // NEGATIVE CONTROL. With no WARN row the filter says so. It is not an empty doctor.
  it('says no row is WARN when the read holds none', async () => {
    vi.mocked(getPreflightDetail).mockResolvedValue({
      ...DETAIL,
      rows: DETAIL.rows.filter((r) => r.status !== 'WARN'),
    });
    render(<DoctorList warnOnly />);
    expect(await screen.findByText('No row is WARN.')).toBeTruthy();
    expect(screen.queryByText('The doctor returned no row.')).toBeNull();
  });
});
