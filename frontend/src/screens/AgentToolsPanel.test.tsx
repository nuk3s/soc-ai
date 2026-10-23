// The Agent tools panel marked enrich_ip, enrich_domain and enrich_hash
// "Available" while every local feed was missing, so an empty answer read as
// "no hit" (dogfood 2026-10-19, R5-D9). The backend now sends `degraded` and
// `state_reason`. A degraded tool reads "Degraded" with its reason. A tool
// with no feed to look in reads "Unavailable" with its reason.
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AgentTool } from '../lib/api';

const getAgentToolsMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAgentTools: getAgentToolsMock,
}));

import { AgentToolsPanel } from './AgentToolsPanel';

type ToolRow = AgentTool & { degraded?: string[]; state_reason?: string | null };

function tool(over: Partial<ToolRow>): ToolRow {
  return {
    name: 'enrich_hash',
    category: 'Enrichment',
    read_only: true,
    description: 'Enrich a file hash against the local blocklists.',
    requires: ['Local blocklists'],
    missing: [],
    available: true,
    degraded: [],
    state_reason: null,
    ...over,
  };
}

function renderPanel(tools: ToolRow[]) {
  getAgentToolsMock.mockResolvedValue({ tools });
  return render(
    <MemoryRouter>
      <AgentToolsPanel />
    </MemoryRouter>,
  );
}

function rowOf(name: string): HTMLElement {
  return screen.getByText(name).closest('div.flex.items-start') as HTMLElement;
}

afterEach(() => {
  // Unmount first. The unmount runs the effects React still owes, and those
  // call the mocks. A reset mock returns undefined and breaks the next tests.
  cleanup();
  getAgentToolsMock.mockReset();
});

describe('AgentToolsPanel feed state', () => {
  it('shows a tool with a stale feed as Degraded with the reason', async () => {
    renderPanel([
      tool({
        degraded: ['Local blocklists'],
        state_reason: 'The tor feed is 88 days old. An empty answer can come from a gap in a feed.',
      }),
    ]);
    await screen.findByText('enrich_hash');
    const row = rowOf('enrich_hash');
    expect(row.textContent).toContain('Degraded');
    expect(row.textContent).not.toContain('Available');
    expect(row.textContent).toContain('The tor feed is 88 days old.');
    expect(row.textContent).toContain('! Local blocklists');
  });

  it('shows a tool with no feed to look in as Unavailable with the reason', async () => {
    renderPanel([
      tool({
        available: false,
        missing: ['Local blocklists'],
        state_reason: 'soc-ai finds no file for urlhaus. The tool has no data to look in.',
      }),
    ]);
    await screen.findByText('enrich_hash');
    const row = rowOf('enrich_hash');
    expect(row.textContent).toContain('Unavailable');
    expect(row.textContent).toContain('The tool has no data to look in.');
    expect(row.textContent).toContain('○ Local blocklists');
  });

  it('shows a tool with fresh feeds as Available with no reason line', async () => {
    renderPanel([tool({})]);
    await screen.findByText('enrich_hash');
    const row = rowOf('enrich_hash');
    expect(row.textContent).toContain('Available');
    expect(row.textContent).toContain('✓ Local blocklists');
    expect(row.querySelector('[data-testid="tool-state-reason"]')).toBeNull();
  });

  it('renders a code span in a reason as code', async () => {
    renderPanel([
      tool({
        degraded: ['Local blocklists'],
        state_reason: 'Run `soc-ai blocklists refresh`.',
      }),
    ]);
    await screen.findByText('enrich_hash');
    expect(rowOf('enrich_hash').querySelector('code')?.textContent).toBe('soc-ai blocklists refresh');
  });
});
