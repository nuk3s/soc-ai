// The cron jobs must be visible in-product (user requirement, 2026-07-16):
// the panel renders the observed backup archives + blocklist freshness, and
// honestly says "has not run" when the dirs are empty.
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

const STATE = vi.hoisted(() => ({
  data: {
    backups: [
      {
        name: 'soc-ai-backup-20260716-0215.tar.gz',
        size_bytes: 48 * 1024 * 1024,
        modified: '2026-07-16T02:15:00+00:00',
      },
    ],
    backups_dir: '/var/lib/soc-ai/data/backups',
    blocklists_dir: '/var/lib/soc-ai/blocklists',
    blocklists_refreshed: '2026-07-16T02:45:00+00:00',
    blocklist_files: 4,
  },
}));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getMaintenance: vi.fn(() => Promise.resolve(STATE.data)),
}));

import { MaintenancePanel } from './MaintenancePanel';

describe('MaintenancePanel', () => {
  it('lists backup archives and blocklist freshness', async () => {
    render(<MaintenancePanel />);
    expect(await screen.findByText('soc-ai-backup-20260716-0215.tar.gz')).toBeTruthy();
    expect(screen.getByText('48.0 MiB')).toBeTruthy();
    expect(screen.getByText(/feed files/)).toBeTruthy();
  });

  it('says so when the crons have not run yet', async () => {
    STATE.data = {
      backups: [],
      backups_dir: '/var/lib/soc-ai/data/backups',
      blocklists_dir: '/var/lib/soc-ai/blocklists',
      blocklists_refreshed: null as unknown as string,
      blocklist_files: 0,
    };
    render(<MaintenancePanel />);
    expect(await screen.findByText(/backup cron has not run/i)).toBeTruthy();
    expect(screen.getByText(/refresh cron has not run/i)).toBeTruthy();
  });
});
