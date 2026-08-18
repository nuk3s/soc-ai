// The hosted demo refuses admin-gated reads (403 `demo_mode`) — a security fix:
// the public demo used to answer the full user table and which secrets are set
// to anyone. The screen's job is to render that refusal as POLICY, not as an
// incident: it is the first thing a demo visitor who clicks Config ever sees,
// and the alarm-red "Couldn't load this view" card read as breakage (it broke
// the public browser smoke exactly that way — Check fitness never rendered,
// because the whole pane was an error card).
//
// The control matters as much as the fix: a REAL failed load must keep the
// alarm card. A demo notice shown for every 403 would hide genuine outages
// behind friendly copy — the inverse mistake, and this codebase's most-shipped
// one.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('./AgentToolsPanel', () => ({ AgentToolsPanel: () => null }));
vi.mock('./ApiKeysPanel', () => ({ ApiKeysPanel: () => null }));
vi.mock('./DataSourcesPanel', () => ({ DataSourcesPanel: () => null }));
vi.mock('./EgressPolicyPanel', () => ({ EgressPolicyPanel: () => null }));
vi.mock('./NotificationsPanel', () => ({ NotificationsPanel: () => null }));
vi.mock('./RedactionPreviewPanel', () => ({ RedactionPreviewPanel: () => null }));
vi.mock('./DetectionTuningPanel', () => ({ DetectionTuningPanel: () => null }));
vi.mock('./MaintenancePanel', () => ({ MaintenancePanel: () => null }));
vi.mock('./RunbooksPanel', () => ({ RunbooksPanel: () => null }));
vi.mock('./AboutPanel', () => ({ AboutPanel: () => null }));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getConfig: vi.fn(),
  listUsers: vi.fn().mockResolvedValue({ users: [] }),
  listDangerSettings: vi.fn().mockResolvedValue([]),
  getGatewayModels: vi.fn().mockResolvedValue({ ok: true, models: [] }),
  getInternalIdentifiers: vi.fn().mockResolvedValue({
    groups: [],
    last_scan: { running: false, last_scan: null, last_summary: null, note: null },
  }),
}));

import { ApiError, getConfig } from '../lib/api';
import { Config } from './Config';

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/config']}>
      <Config />
    </MemoryRouter>,
  );

beforeEach(() => vi.clearAllMocks());

describe('Config under the demo read lock', () => {
  it('renders the refusal as policy, not as an outage', async () => {
    vi.mocked(getConfig).mockRejectedValue(
      new ApiError('Demo — read-only; admin config is disabled.', 403, 'demo_mode'),
    );
    mount();

    expect(await screen.findByText('Read-only demo')).toBeTruthy();
    // Both halves, because each alone is satisfiable by the wrong render:
    // the calm notice present, AND the alarm card absent.
    expect(screen.queryByText(/Couldn't load this view/)).toBeNull();
  });

  it('keeps the alarm card for a real failed load', async () => {
    // The control: a plain outage (or any non-demo error) must never wear the
    // friendly demo copy. Note it is a 403 too — the discriminator is the
    // REASON, not the status, per the ApiError contract.
    vi.mocked(getConfig).mockRejectedValue(new ApiError('admin required', 403, 'admin_required'));
    mount();

    expect(await screen.findByText(/Couldn't load this view/)).toBeTruthy();
    expect(screen.queryByText('Read-only demo')).toBeNull();
  });
});
