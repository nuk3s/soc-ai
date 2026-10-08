// Dogfood 2026-10-06 W8: the draft confirm box showed the id and one dry-run
// line. The definition was readable only after the save. The findings were
// numbered from 0 in the version note and from nothing on the page. A
// candidate offered only "Run in shadow" and had no Discard.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
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
  draftAnalytic: vi.fn(),
  setAnalyticStatus: vi.fn(),
}));

import { draftAnalytic, getAbout, getHunt, setAnalyticStatus, type AnalyticRow } from '../lib/api';
import { AnalyticActions } from '../components/AnalyticDrawer';
import { HuntDetail } from './HuntDetail';

const about: AboutInfo = {
  version: '1.0.0',
  repo_url: 'https://example.test/soc-ai',
  license: 'MIT',
  update_check_enabled: false,
  general_chat_enabled: true,
  sigma_authoring_enabled: false,
};

const threat = (title: string) => ({
  title,
  detail: 'd',
  severity: 'high',
  category: 'threat',
  hosts: ['198.51.100.7'],
  citations: ['tel-doc-000001'],
});

const hunt: HuntDetailData = {
  id: 'H-8',
  objective: 'hunt for id command execution',
  kind: 'chat',
  status: 'complete',
  narrative: '',
  findings: [threat('A web shell runs whoami'), threat('HTTP service executes id command as root')],
  affectedHosts: [],
  mitreTechniques: [],
  recommendedActions: [],
  confidence: 0.7,
  startedBy: 'analyst',
  elapsedLabel: '6m',
  elapsedSec: 360,
  ts: '2026-10-06T00:00:00Z',
  timeline: [],
  diff: null,
  outcome: 'threat_found',
};

const PREVIEW = {
  analytic_id: 'local-http-service-executes-id',
  spec_yaml: 'id: local-http-service-executes-id\ntitle: An HTTP service executes id\n',
  rationale: 'r',
  status: 'preview',
  dry_run: { ran: true, hit_count: 0, sample_ids: [], window_days: 30, error: null },
  review: {
    title: 'An HTTP service executes the id command',
    logic: 'It matches a document where event.dataset is suricata.alert, grouped by destination.ip.',
    false_positives: ['A health check that runs id.'],
    source: 'Source finding: 0 of 3 documents match. They are older than the 30-day dry run.',
    repeats_alerts: 'This analytic repeats 2 Suricata rules. They raise alerts already.',
  },
};

function mount() {
  return render(
    <MemoryRouter initialEntries={['/hunts/H-8']}>
      <Routes>
        <Route path="/hunts/:id" element={<HuntDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('HuntDetail draft confirm box', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about);
    vi.mocked(getHunt).mockResolvedValue(hunt);
  });

  it('numbers the findings from F1, the number the version note prints', async () => {
    mount();
    await screen.findAllByTestId('finding-number');
    expect(screen.getAllByTestId('finding-number').map((n) => n.textContent)).toEqual([
      'F1',
      'F2',
    ]);
  });

  it('shows the draft, its checks and its YAML before the save', async () => {
    vi.mocked(draftAnalytic).mockResolvedValue(PREVIEW);
    mount();
    await screen.findAllByTestId('finding-number');
    fireEvent.click(screen.getAllByTestId('draft-analytic')[1]);
    await screen.findByTestId('draft-analytic-confirm');
    expect(draftAnalytic).toHaveBeenCalledWith('H-8', 1, { preview: true });
    const review = screen.getByTestId('draft-analytic-review');
    expect(review.textContent).toContain('An HTTP service executes the id command');
    expect(screen.getByTestId('draft-analytic-logic').textContent).toContain('suricata.alert');
    expect(screen.getByTestId('draft-analytic-repeats').textContent).toBe(
      'This analytic repeats 2 Suricata rules. They raise alerts already.',
    );
    expect(screen.getByTestId('draft-analytic-source').textContent).toBe(
      'Source finding: 0 of 3 documents match. They are older than the 30-day dry run.',
    );
    expect(review.textContent).toContain('A health check that runs id.');
    expect(screen.queryByTestId('draft-analytic-yaml')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Show the YAML' }));
    expect(screen.getByTestId('draft-analytic-yaml').textContent).toContain(
      'id: local-http-service-executes-id',
    );
  });

  it('shows no check lines when the server sent none', async () => {
    // Negative control: an older server sends no review, and the box keeps
    // its id and its dry-run line only.
    vi.mocked(draftAnalytic).mockResolvedValue({ ...PREVIEW, review: null });
    mount();
    await screen.findAllByTestId('finding-number');
    fireEvent.click(screen.getAllByTestId('draft-analytic')[0]);
    await screen.findByTestId('draft-analytic-confirm');
    expect(screen.queryByTestId('draft-analytic-review')).toBeNull();
    expect(screen.queryByTestId('draft-analytic-repeats')).toBeNull();
  });
});

describe('AnalyticActions on a candidate', () => {
  const candidate = {
    id: 'local-http-service-executes-id',
    title: 't',
    level: 'high',
    evaluator: 'match',
    scope_kind: 'host',
    tier: 'local',
    status: 'candidate',
    observations_7d: 0,
    leads_7d: 0,
    hunted_7d: 0,
    dismissed_7d: 0,
    shadow_hits_7d: 0,
    unread_shadow_hits: 0,
  } as AnalyticRow;

  it('discards a candidate with a reason', async () => {
    vi.mocked(setAnalyticStatus).mockResolvedValue(candidate);
    render(
      <MemoryRouter>
        <AnalyticActions analytic={candidate} />
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Discard' }));
    const input = screen.getByPlaceholderText('Why you discard it');
    // The confirm waits for a reason.
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeDisabled();
    fireEvent.change(input, { target: { value: 'it repeats two rules' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() =>
      expect(setAnalyticStatus).toHaveBeenCalledWith(
        'local-http-service-executes-id',
        'retired',
        'it repeats two rules',
      ),
    );
  });
});
