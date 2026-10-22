// The Settings tour names anchors on the page and in its section nav. This
// smoke test opens Settings on a first visit, with no stored section, so the
// page shows its first section, and every anchor of the tour is on the page.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SETTINGS_TOUR } from '../tours/content';
import { missingAnchors } from '../tours/testing';

vi.mock('./AgentToolsPanel', () => ({ AgentToolsPanel: () => null }));
vi.mock('./ApiKeysPanel', () => ({ ApiKeysPanel: () => null }));
vi.mock('./DataSourcesPanel', () => ({ DataSourcesPanel: () => null }));
vi.mock('./EgressPolicyPanel', () => ({ EgressPolicyPanel: () => null }));
vi.mock('./NotificationsPanel', () => ({ NotificationsPanel: () => null }));
vi.mock('./RedactionPreviewPanel', () => ({ RedactionPreviewPanel: () => null }));
vi.mock('./DetectionTuningPanel', () => ({ DetectionTuningPanel: () => null }));
vi.mock('./MaintenancePanel', () => ({ MaintenancePanel: () => null }));
vi.mock('./RunbooksPanel', () => ({ RunbooksPanel: () => null }));

// One mixed group: a day-1 row and a row behind the Advanced fold.
const GROUPS = vi.hoisted(() => [
  {
    title: 'Investigation model',
    parent: 'Models & Reasoning',
    items: [
      {
        key: 'investigate_when_unsure',
        label: 'Investigate when unsure',
        help: 'Run the investigation loop when the evidence does not back the first verdict.',
        source: 'default',
        apply: 'hot-apply',
        type: 'toggle',
        value: true,
        day1: true,
      },
      {
        key: 'general_chat_enabled',
        label: 'General chat',
        help: 'Allow the general scope of Ask soc-ai.',
        source: 'default',
        apply: 'restart',
        type: 'toggle',
        value: true,
        day1: false,
      },
    ],
  },
]);

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getConfig: vi.fn(() => Promise.resolve({ groups: GROUPS, tokens: [], users: [], dangerHost: '' })),
  listUsers: vi.fn().mockResolvedValue({ users: [] }),
  listDangerSettings: vi.fn().mockResolvedValue([]),
  getGatewayModels: vi.fn().mockResolvedValue({ ok: true, models: [] }),
  getInternalIdentifiers: vi.fn().mockResolvedValue({
    groups: [],
    last_scan: { running: false, last_scan: null, last_summary: null, note: null },
  }),
}));

import { Config } from './Config';

beforeEach(() => {
  localStorage.clear();
});

describe('the Settings tour', () => {
  it('finds every anchor on the first visit', async () => {
    render(
      <MemoryRouter initialEntries={['/config']}>
        <Config />
      </MemoryRouter>,
    );
    await screen.findByText('investigate_when_unsure');
    expect(missingAnchors(SETTINGS_TOUR)).toEqual([]);
    // The row anchor sits on the first row on screen, and on one row only.
    const rows = document.querySelectorAll('[data-tour="settings-row"]');
    expect(rows).toHaveLength(1);
    expect(rows[0].getAttribute('data-setting-key')).toBe('investigate_when_unsure');
  });
});
