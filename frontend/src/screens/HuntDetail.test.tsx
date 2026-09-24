// Merge 5 — "Draft an analytic" on a hunt finding card. The drafter writes one
// catalog analytic from the finding and stores it in the local tier as a
// candidate. A candidate never runs, so there is no confirm-first gate here;
// the gate is the finding's category. Only a threat finding can become an
// analytic: a visibility gap reports telemetry this grid does not have.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AboutInfo, HuntDetailData } from '../lib/types';

const { navigate } = vi.hoisted(() => ({ navigate: vi.fn() }));

vi.mock('react-router-dom', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-router-dom')>()),
  useNavigate: () => navigate,
}));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunt: vi.fn(),
  promoteFinding: vi.fn(),
  cancelHuntConsole: vi.fn(),
  deleteHunt: vi.fn(),
  startHuntConsole: vi.fn(),
  getHuntChat: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  postHuntChat: vi.fn(),
  getAbout: vi.fn(),
  draftFindingDetection: vi.fn(),
  draftAnalytic: vi.fn(),
}));

import { draftAnalytic, getAbout, getHunt } from '../lib/api';
import { DEFINE_HUNT } from '../lib/tooltips';
import { HuntDetail } from './HuntDetail';

const about: AboutInfo = {
  version: '1.0.0',
  repo_url: 'https://example.test/soc-ai',
  license: 'MIT',
  update_check_enabled: false,
  general_chat_enabled: true,
  sigma_authoring_enabled: false,
};

const HUNT_ID = 'H-5';

const threat = {
  title: 'An RC4 service ticket is issued to a workstation account',
  detail: 'One workstation account requested a service ticket with RC4 encryption.',
  severity: 'high',
  category: 'threat',
  hosts: ['198.51.100.7'],
  citations: ['tel-doc-000001'],
};

const gap = {
  title: 'This grid has no Kerberos telemetry',
  detail: 'No dataset on this grid carries Kerberos ticket requests.',
  severity: 'info',
  category: 'visibility_gap',
  hosts: [] as string[],
  citations: [] as string[],
};

function huntFixture(findings: HuntDetailData['findings']): HuntDetailData {
  return {
    id: HUNT_ID,
    objective: 'hunt for service ticket abuse',
    kind: 'chat',
    status: 'complete',
    narrative: '',
    findings,
    affectedHosts: [],
    mitreTechniques: [],
    recommendedActions: [],
    confidence: 0.72,
    startedBy: 'analyst',
    elapsedLabel: '2m 10s',
    elapsedSec: 130,
    ts: '2026-09-17T00:00:00Z',
    timeline: [],
    diff: null,
  };
}

function mount() {
  return render(
    <MemoryRouter initialEntries={[`/hunts/${HUNT_ID}`]}>
      <Routes>
        <Route path="/hunts/:id" element={<HuntDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

const DRAFT = {
  analytic_id: 'local-rc4-ticket-from-workstation',
  spec_yaml: 'id: local-rc4-ticket-from-workstation\n',
  rationale: 'It fires on an RC4 service ticket for a workstation account.',
  status: 'candidate',
  dry_run: {
    ran: true,
    hit_count: 3,
    sample_ids: ['tel-doc-000001'],
    window_days: 30,
    error: null,
  },
};

describe('HuntDetail — draft an analytic from a finding', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about);
  });

  it('offers the action on a threat finding and not on a visibility gap', async () => {
    vi.mocked(getHunt).mockResolvedValue(huntFixture([threat, gap]));
    mount();
    await screen.findByText(threat.title);
    const buttons = screen.getAllByRole('button', { name: /draft an analytic/i });
    expect(buttons).toHaveLength(1);
  });

  it('posts the draft and shows the candidate id with its dry run', async () => {
    vi.mocked(getHunt).mockResolvedValue(huntFixture([threat]));
    vi.mocked(draftAnalytic).mockResolvedValue(DRAFT);
    mount();
    await screen.findByText(threat.title);
    fireEvent.click(screen.getByRole('button', { name: /draft an analytic/i }));

    await waitFor(() => expect(draftAnalytic).toHaveBeenCalledWith(HUNT_ID, 0));
    expect(
      await screen.findByText(/Candidate local-rc4-ticket-from-workstation written\./i),
    ).toBeInTheDocument();
    expect(screen.getByText(/Dry run over 30 days: 3 matches\./i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /open the analytics tab/i })).toHaveAttribute(
      'href',
      '/hunts?tab=analytics',
    );
    // The action is spent: the button goes once the candidate exists.
    expect(screen.queryByRole('button', { name: /draft an analytic/i })).toBeNull();
  });

  it('shows the hint of a refused draft and leaves the button clickable', async () => {
    vi.mocked(getHunt).mockResolvedValue(huntFixture([threat]));
    vi.mocked(draftAnalytic).mockRejectedValue(
      new Error('a drafted analytic id must start with local-'),
    );
    mount();
    await screen.findByText(threat.title);
    const btn = screen.getByRole('button', { name: /draft an analytic/i });
    fireEvent.click(btn);

    await screen.findByText(/must start with local-/i);
    expect(btn).not.toBeDisabled();
  });

  it('says the dry run did not run rather than reporting zero matches', async () => {
    vi.mocked(getHunt).mockResolvedValue(huntFixture([threat]));
    vi.mocked(draftAnalytic).mockResolvedValue({
      ...DRAFT,
      dry_run: {
        ran: false,
        hit_count: 0,
        sample_ids: [],
        window_days: 30,
        error: 'mapping error',
      },
    });
    mount();
    await screen.findByText(threat.title);
    fireEvent.click(screen.getByRole('button', { name: /draft an analytic/i }));

    expect(await screen.findByText(/The dry run did not run\./i)).toBeInTheDocument();
    expect(screen.queryByText(/0 matches/i)).toBeNull();
  });
});

// INCONCLUSIVE, then the objective, then a banner that said "this hunt ended
// in an error" and nothing more. The backend stores the sentence that names
// the failure. It belongs at the top, where the verdict is.
describe('HuntDetail — why an errored hunt failed', () => {
  beforeEach(() => {
    vi.mocked(getAbout).mockResolvedValue(about);
  });

  const errored = (narrative: string): HuntDetailData => ({
    ...huntFixture([]),
    status: 'error',
    narrative,
    confidence: null,
  });

  it('prints the stored failure sentence under the heading', async () => {
    vi.mocked(getHunt).mockResolvedValue(
      errored('The grid refused every query. Elasticsearch answered 503 for 4 minutes.'),
    );
    mount();
    const line = await screen.findByTestId('hunt-failure-reason');
    expect(line.textContent).toBe(
      'The grid refused every query. Elasticsearch answered 503 for 4 minutes.',
    );
  });

  it('says no reason was recorded rather than showing nothing', async () => {
    vi.mocked(getHunt).mockResolvedValue(errored(''));
    mount();
    const line = await screen.findByTestId('hunt-failure-reason');
    expect(line.textContent).toBe('The hunt failed. No reason was recorded.');
  });

  it('leaves a complete hunt alone', async () => {
    vi.mocked(getHunt).mockResolvedValue(huntFixture([threat]));
    mount();
    await screen.findByText(threat.title);
    expect(screen.queryByTestId('hunt-failure-reason')).toBeNull();
  });
});

// One entity, one address. The lead page, the host page and the hit card send
// an address to /hosts/<address>; the hunt page sent the same address to
// /entity/<address>, so one host had two pages and neither knew about the
// other.
describe('HuntDetail host links', () => {
  beforeEach(() => {
    vi.mocked(getAbout).mockResolvedValue(about);
  });

  it('sends an address to the host page from a finding and from the panel', async () => {
    vi.mocked(getHunt).mockResolvedValue({
      ...huntFixture([threat]),
      affectedHosts: ['198.51.100.7'],
    });
    mount();
    await screen.findByText(threat.title);
    for (const link of screen.getAllByRole('link', { name: '198.51.100.7' })) {
      expect(link.getAttribute('href')).toBe('/hosts/198.51.100.7');
    }
  });

  it('keeps a name on the entity page', async () => {
    vi.mocked(getHunt).mockResolvedValue({
      ...huntFixture([{ ...threat, hosts: ['svc_sql'] }]),
      affectedHosts: ['svc_sql'],
    });
    mount();
    await screen.findByText(threat.title);
    for (const link of screen.getAllByRole('link', { name: 'svc_sql' })) {
      expect(link.getAttribute('href')).toBe('/entity/svc_sql');
    }
  });
});

// The hunt page and the Hunts list read one sentence for one noun. The page an
// analyst opens from a link never showed the list's line.
describe('HuntDetail says what a hunt is', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about);
  });

  it('carries the definition line under the title', async () => {
    vi.mocked(getHunt).mockResolvedValue(huntFixture([threat]));
    mount();
    const line = await screen.findByTestId('define-hunt');
    expect(line.textContent).toContain(DEFINE_HUNT);
  });
});
