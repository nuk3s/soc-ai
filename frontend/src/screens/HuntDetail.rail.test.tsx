// Dogfood 2026-10-06 C5: the lead 6 hunt found no DCSync and showed
// T1003.006. A hunt that found no traffic showed "Affected hosts 2". The
// recommended actions held steps the analyst cannot take from the console.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AboutInfo, HuntDetailData } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunt: vi.fn(),
  getHunts: vi.fn().mockResolvedValue([]),
  getLead: vi.fn(),
  getHuntChat: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  postHuntChat: vi.fn(),
  getAbout: vi.fn(),
}));

import { getAbout, getHunt } from '../lib/api';
import { huntHosts } from '../lib/huntGraph';
import { HuntDetail } from './HuntDetail';

const about: AboutInfo = {
  version: '1.0.0',
  repo_url: 'https://example.test/soc-ai',
  license: 'MIT',
  update_check_enabled: false,
  general_chat_enabled: true,
  sigma_authoring_enabled: false,
};

function hunt(over: Partial<HuntDetailData>): HuntDetailData {
  return {
    id: 'H-6',
    objective: 'hunt for dcsync',
    kind: 'chat',
    status: 'complete',
    narrative: 'n',
    findings: [],
    affectedHosts: ['10.1.10.11', '10.1.10.12'],
    mitreTechniques: ['T1003.006'],
    recommendedActions: [{ title: 'Promote finding F1', rationale: 'r' }],
    operatorActions: [{ title: 'Re-extend the events window beyond 30 days', rationale: 'r2' }],
    confidence: 0.6,
    startedBy: 'analyst',
    elapsedLabel: '6m',
    elapsedSec: 360,
    ts: '2026-10-06T00:00:00Z',
    timeline: [],
    diff: null,
    ...over,
  };
}

function mount() {
  return render(
    <MemoryRouter initialEntries={['/hunts/H-6']}>
      <Routes>
        <Route path="/hunts/:id" element={<HuntDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('HuntDetail right rail', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about);
  });

  it('names hosts and no technique when the hunt found no threat', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt({ outcome: 'no_threat' }));
    mount();
    expect(await screen.findByText('Hosts named')).toBeInTheDocument();
    expect(screen.queryByText('Affected hosts')).toBeNull();
    expect(screen.queryByText('MITRE ATT&CK')).toBeNull();
  });

  it('keeps affected hosts and the technique beside a threat', async () => {
    // Negative control: a threat finding supports both.
    vi.mocked(getHunt).mockResolvedValue(
      hunt({
        outcome: 'threat_found',
        findings: [
          {
            title: 'replication request',
            detail: 'd',
            severity: 'medium',
            category: 'threat',
            hosts: [],
            citations: [],
            validatorNote:
              'Severity held at medium. The finding cites alerts only. An investigation can raise it.',
          },
        ],
      }),
    );
    mount();
    // The report of a threat hunt marks its hosts affected. The panel names
    // the hosts and marks the affected ones (AB3).
    expect(await screen.findByText('Hosts named')).toBeInTheDocument();
    expect(screen.getByTestId('hunt-hosts-affected').textContent).toBe(
      '2 affected: a threat finding or the report names them.',
    );
    expect(screen.getByText('MITRE ATT&CK')).toBeInTheDocument();
    expect(
      screen.getByText(
        'Severity held at medium. The finding cites alerts only. An investigation can raise it.',
      ),
    ).toBeInTheDocument();
  });

  it('counts the hosts of the findings and of the report in one list with the map', async () => {
    // Dogfood 2026-11-17, AB3: "Hosts named 12" from the report stood beside
    // a map of 18 hosts from the findings.
    vi.mocked(getHunt).mockResolvedValue(
      hunt({
        outcome: 'no_threat',
        affectedHosts: ['10.1.10.11', '10.1.10.12'],
        findings: [
          {
            title: 'beacon is ntp',
            detail: 'd',
            severity: 'info',
            category: 'observation',
            hosts: ['10.1.10.11', '10.1.10.21', '10.1.10.22'],
            citations: [],
          },
        ],
      }),
    );
    mount();
    expect(await screen.findByText('Hosts named')).toBeInTheDocument();
    expect(screen.getByTestId('hunt-hosts-count').textContent).toBe('4');
    expect(huntHosts(
      [{ title: 't', detail: 'd', severity: 'info', category: 'observation', hosts: ['10.1.10.11', '10.1.10.21', '10.1.10.22'], citations: [] }],
      ['10.1.10.11', '10.1.10.12'],
    ).length).toBe(4);
    // NEGATIVE CONTROL: a hunt that found no threat marks no host affected.
    expect(screen.queryByTestId('hunt-hosts-affected')).toBeNull();
  });

  it('marks a host that a threat finding names, whatever the stored outcome word', async () => {
    // The demo hunt read "threats_confirmed", and the panel marked nothing.
    vi.mocked(getHunt).mockResolvedValue(
      hunt({
        outcome: 'threats_confirmed',
        affectedHosts: [],
        findings: [
          { title: 'beacon', detail: 'd', severity: 'high', category: 'threat', hosts: ['10.1.10.31'], citations: [] },
        ],
      }),
    );
    mount();
    expect((await screen.findByTestId('hunt-hosts-affected')).textContent).toBe(
      '1 affected: a threat finding or the report names it.',
    );
  });

  it('lists the operator steps apart from the console actions', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt({ outcome: 'no_threat' }));
    mount();
    expect(await screen.findByText('Promote finding F1')).toBeInTheDocument();
    expect(screen.queryByText('Re-extend the events window beyond 30 days')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: '1 step needs the operator' }));
    expect(screen.getByText('Re-extend the events window beyond 30 days')).toBeInTheDocument();
  });
});
