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
  getApiKeys: vi.fn(),
}));

import { ApiError, getApiKeys, getPreflightDetail, refreshPreflight } from '../lib/api';
import type { PreflightDetail } from '../lib/types';
import { ShellProvider } from '../shell/ShellContext';
import { DoctorList, doctorCounts } from './DoctorList';

const DETAIL: PreflightDetail = {
  checked_at: new Date(Date.now() - 120_000).toISOString(),
  rows: [
    { name: 'blocklists', status: 'WARN', detail: 'no feed is loaded', hint: 'Run soc-ai blocklists refresh.' },
    { name: 'network model', status: 'INFO', detail: 'off. The extra package that the network model needs is installed.', hint: '' },
    { name: 'prompt assets', status: 'PASS', detail: '2 assets are present', hint: '' },
    { name: 'oracle route', status: 'PASS', detail: 'the route answers', hint: '' },
  ],
};

beforeEach(() => {
  vi.mocked(getPreflightDetail).mockReset().mockResolvedValue(DETAIL);
  vi.mocked(refreshPreflight).mockReset();
  vi.mocked(getApiKeys).mockReset().mockResolvedValue([]);
});

describe('DoctorList', () => {
  it('shows every row, the INFO and PASS rows too, with its status and detail', async () => {
    render(<DoctorList />);
    const estate = await screen.findByTestId('doctor-row-network model');
    expect(within(estate).getByTestId('doctor-status').textContent).toBe('INFO');
    expect(estate.textContent).toContain('off. The extra package that the network model needs is installed.');
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
    expect(within(screen.getByTestId('doctor-row-network model')).queryByTestId('doctor-fix')).toBeNull();
  });

  // Round 2 (V2-3): a remedy showed its backticks raw: "Run `soc-ai
  // blocklists refresh` to fetch ...". The fix line renders a code span.
  it('renders the code spans of a fix line without the backticks', async () => {
    vi.mocked(getPreflightDetail).mockResolvedValue({
      checked_at: new Date().toISOString(),
      rows: [
        {
          name: 'blocklists',
          status: 'WARN',
          detail: 'never refreshed: tor',
          hint: 'Run `soc-ai blocklists refresh` to fetch the Tor feed. Or remove `tor` from `blocklist_sources`.',
        },
      ],
    });
    render(<DoctorList />);
    const fix = within(await screen.findByTestId('doctor-row-blocklists')).getByTestId('doctor-fix');
    expect(fix.textContent).toBe(
      'Run soc-ai blocklists refresh to fetch the Tor feed. Or remove tor from blocklist_sources.',
    );
    expect([...fix.querySelectorAll('code')].map((c) => c.textContent)).toEqual([
      'soc-ai blocklists refresh',
      'tor',
      'blocklist_sources',
    ]);
  });

  it('runs the checks again on Refresh and shows the new rows', async () => {
    vi.mocked(refreshPreflight).mockResolvedValue({
      checked_at: new Date().toISOString(),
      rows: [{ name: 'network model', status: 'INFO', detail: 'learning. No fit is on record yet.', hint: '' }],
    });
    render(<DoctorList />);
    await screen.findByTestId('doctor-row-network model');
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    await waitFor(() => expect(refreshPreflight).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(screen.getByTestId('doctor-row-network model').textContent).toContain('learning.'),
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
    expect(screen.queryByTestId('doctor-row-network model')).toBeNull();
    // The header counts every row of the read, not the filtered list. The
    // count goes up in an effect after the rows render.
    await waitFor(() => expect(seen).toEqual([4]));
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


// L3 (review 2026-11-12): three warnings sat at rows 21, 34 and 35 of 36, as
// text only. FAIL and WARN rows come first, each with a control to its fix.
const REVIEW_ROWS: PreflightDetail = {
  checked_at: new Date().toISOString(),
  rows: [
    { name: 'analyst model', status: 'PASS', detail: 'the model is served', hint: '' },
    { name: 'egress', status: 'INFO', detail: 'zero egress: no.', hint: '' },
    {
      name: 'admin password',
      status: 'WARN',
      detail: 'the admin account still uses the generated password.',
      hint: 'Sign in as admin. Open the account menu and select Change password.',
    },
    { name: 'tls', status: 'INFO', detail: 'TLS terminates at the proxy.', hint: '' },
    {
      name: 'blocklists',
      status: 'WARN',
      detail: 'never refreshed: urlhaus, threatfox, feodo',
      hint:
        'ABUSE_CH_AUTH_KEY is not set, so `soc-ai blocklists refresh` skips these feeds. ' +
        'To clear the warning, register at https://auth.abuse.ch/ and set ABUSE_CH_AUTH_KEY. ' +
        'Or remove `feodo` from `blocklist_sources`. Triage continues with stale or absent feeds. See docs/BLOCKLISTS.md.',
    },
    {
      name: 'backups',
      status: 'WARN',
      detail: 'the newest backup archive in /data/backups is 20 days old.',
      hint:
        'Run `mkdir -p /data/backups && cd /data/backups && soc-ai backup` from a nightly host cron job. ' +
        'See docs/DOCKER.md, Backup schedule and retention.',
    },
    { name: 'index pattern', status: 'FAIL', detail: 'no index matches', hint: '' },
  ],
};

describe('DoctorList, the warnings first with a fix', () => {
  it('lists FAIL, then WARN, then the rest in the doctor order', async () => {
    vi.mocked(getPreflightDetail).mockResolvedValue(REVIEW_ROWS);
    render(<DoctorList />);
    await screen.findByTestId('doctor-row-backups');
    const names = screen.getAllByTestId(/^doctor-row-/).map((li) => li.dataset.testid?.replace('doctor-row-', ''));
    expect(names).toEqual([
      'index pattern',
      'admin password',
      'blocklists',
      'backups',
      'analyst model',
      'egress',
      'tls',
    ]);
  });

  it('gives each warning the control that fixes it', async () => {
    vi.mocked(getPreflightDetail).mockResolvedValue(REVIEW_ROWS);
    vi.mocked(getApiKeys).mockResolvedValue([
      { key: 'abuse_ch_auth_key', label: 'abuse.ch Auth-Key', help: '', isSet: false, source: 'unset', canStore: true } as never,
    ]);
    render(<DoctorList />);
    const password = await screen.findByTestId('doctor-row-admin password');
    expect(within(password).getByTestId('doctor-fix-password').textContent).toBe('Change password');

    const blocklists = screen.getByTestId('doctor-row-blocklists');
    await waitFor(() =>
      expect(within(blocklists).getByTestId('doctor-fix-setting').textContent).toBe(
        'Open the setting abuse.ch Auth-Key',
      ),
    );
    expect(within(blocklists).getByTestId('doctor-fix-setting').getAttribute('href')).toBe('/app/config#api-keys');
    expect(within(blocklists).getByTestId('doctor-fix-command').textContent).toBe('soc-ai blocklists refresh');
    expect(within(blocklists).getByTestId('doctor-fix-doc').getAttribute('href')).toBe(
      'https://nuk3s.github.io/soc-ai/BLOCKLISTS/',
    );

    const backups = screen.getByTestId('doctor-row-backups');
    expect(within(backups).getByTestId('doctor-fix-command').textContent).toBe(
      'mkdir -p /data/backups && cd /data/backups && soc-ai backup',
    );
    expect(within(backups).getByTestId('doctor-fix-doc').getAttribute('href')).toBe(
      'https://nuk3s.github.io/soc-ai/DOCKER/#backup-schedule-and-retention',
    );
    expect(within(backups).getByTestId('doctor-fix-panel').textContent).toBe('Open Scheduled maintenance');
  });

  it('opens the password dialog from the row', async () => {
    vi.mocked(getPreflightDetail).mockResolvedValue(REVIEW_ROWS);
    render(
      <ShellProvider>
        <DoctorList />
      </ShellProvider>,
    );
    fireEvent.click(await screen.findByTestId('doctor-fix-password'));
    expect(await screen.findByRole('dialog', { name: 'Change password' })).toBeTruthy();
  });

  it('gives a PASS or INFO row no control', async () => {
    // NEGATIVE CONTROL: a row with nothing to fix carries no button.
    vi.mocked(getPreflightDetail).mockResolvedValue(REVIEW_ROWS);
    render(<DoctorList />);
    await screen.findByTestId('doctor-row-tls');
    expect(within(screen.getByTestId('doctor-row-tls')).queryByTestId('doctor-fix-controls')).toBeNull();
    expect(within(screen.getByTestId('doctor-row-analyst model')).queryByTestId('doctor-fix-controls')).toBeNull();
  });
});
