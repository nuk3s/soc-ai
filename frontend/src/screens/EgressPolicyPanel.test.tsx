// The egress policy rows name a setting by its label and its section in
// Settings (dogfood 2026-10-19, R5 STE items 34 and 35). The panel renders the
// detail and the redaction through HelpText, so the section is a link.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { EgressPolicy } from '../lib/api';

const POLICY = vi.hoisted(
  (): EgressPolicy => ({
    zero_egress: true,
    destinations: [
      {
        id: 'analyst_cloud',
        label: 'Investigation model',
        enabled: false,
        redaction:
          'none. The model gateway gets the real identifiers. If the gateway routes to a cloud model, turn on "Redact internal identifiers for a cloud model" in Settings > Agent.',
        detail: 'soc-ai sends every investigation to the model m.',
        count_7d: null,
      },
      {
        id: 'update_check',
        label: 'Release check (GitHub)',
        enabled: false,
        redaction: 'none. soc-ai sends nothing about the deployment.',
        detail: 'An opt-in version check behind the Check for updates button in Settings > About.',
        count_7d: null,
      },
    ],
  }),
);

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getEgressPolicy: vi.fn(() => Promise.resolve(POLICY)),
}));

import { EgressPolicyPanel } from './EgressPolicyPanel';

describe('EgressPolicyPanel', () => {
  it('links the section a redaction row names', async () => {
    render(
      <MemoryRouter>
        <EgressPolicyPanel />
      </MemoryRouter>,
    );
    const link = await screen.findByRole('link', { name: 'Settings > Agent' });
    expect(link.getAttribute('href')).toBe('/config#agent');
  });

  it('links the section a detail line names', async () => {
    render(
      <MemoryRouter>
        <EgressPolicyPanel />
      </MemoryRouter>,
    );
    const link = await screen.findByRole('link', { name: 'Settings > About' });
    expect(link.getAttribute('href')).toBe('/config#about');
  });
});
