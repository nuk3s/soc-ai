// Merge 5 — "Draft an analytic" on a hunt finding card. The drafter writes one
// catalog analytic from the finding and stores it in the local tier as a
// candidate. The gate is the finding's category: only a threat finding can
// become an analytic. A visibility gap reports telemetry this grid does not
// have. F1: the click drafts and stores nothing, and a confirm that names the
// id stores it.
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

import { ApiError, draftAnalytic, getAbout, getHunt } from '../lib/api';
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

const PREVIEW = {
  analytic_id: 'local-rc4-ticket-from-workstation',
  spec_yaml: 'id: local-rc4-ticket-from-workstation\n',
  rationale: 'It fires on an RC4 service ticket for a workstation account.',
  status: 'preview',
  dry_run: {
    ran: true,
    hit_count: 3,
    sample_ids: ['tel-doc-000001'],
    window_days: 30,
    error: null,
  },
};

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
    // The gap badge says the gap is one type of telemetry on the grid or the host.
    const badge = screen.getByText('visibility gap');
    expect(badge.getAttribute('title')).toMatch(/this grid or this host does not ship/);
    expect(badge.getAttribute('title')).not.toMatch(/telemetry that this grid does not have/);
  });

  it('drafts on the click, stores on the confirm, and links the candidate', async () => {
    vi.mocked(getHunt).mockResolvedValue(huntFixture([threat]));
    let release: (v: typeof PREVIEW) => void = () => undefined;
    vi.mocked(draftAnalytic)
      .mockImplementationOnce(() => new Promise((r) => (release = r as never)))
      .mockResolvedValueOnce(DRAFT);
    mount();
    await screen.findByText(threat.title);
    fireEvent.click(screen.getByRole('button', { name: /draft an analytic/i }));

    // The click stores nothing and the button cannot fire twice.
    await waitFor(() => expect(draftAnalytic).toHaveBeenCalledWith(HUNT_ID, 0, { preview: true }));
    expect(screen.getByRole('button', { name: /drafting/i })).toBeDisabled();
    release(PREVIEW);

    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain(
      'Save the analytic local-rc4-ticket-from-workstation as a candidate?',
    );
    expect(dialog.textContent).toContain('A candidate does not run.');
    expect(dialog.textContent).toContain('Dry run over 30 days: 3 matches.');
    expect(screen.queryByRole('button', { name: /draft an analytic/i })).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: /save candidate/i }));
    await waitFor(() =>
      expect(draftAnalytic).toHaveBeenLastCalledWith(HUNT_ID, 0, { specYaml: DRAFT.spec_yaml }),
    );
    const saved = await screen.findByTestId('draft-analytic-saved');
    expect(saved.textContent).toContain('local-rc4-ticket-from-workstation saved.');
    expect(
      screen.getByRole('link', { name: 'local-rc4-ticket-from-workstation' }),
    ).toHaveAttribute('href', '/hunts?tab=analytics&open=local-rc4-ticket-from-workstation');
    // The action is spent: the button goes once the candidate exists.
    expect(screen.queryByRole('button', { name: /draft an analytic/i })).toBeNull();
    expect(draftAnalytic).toHaveBeenCalledTimes(2);
  });

  it('links the analytic a finding already has and offers no second draft', async () => {
    vi.mocked(getHunt).mockResolvedValue(
      huntFixture([{ ...threat, analyticId: 'local-already-there' }]),
    );
    mount();
    await screen.findByText(threat.title);
    expect(screen.queryByRole('button', { name: /draft an analytic/i })).toBeNull();
    expect(screen.getByRole('link', { name: 'local-already-there' })).toHaveAttribute(
      'href',
      '/hunts?tab=analytics&open=local-already-there',
    );
  });

  it('reads the hunt again when the server says the finding has an analytic', async () => {
    vi.mocked(getHunt)
      .mockResolvedValueOnce(huntFixture([threat]))
      .mockResolvedValue(huntFixture([{ ...threat, analyticId: 'local-first' }]));
    vi.mocked(draftAnalytic).mockRejectedValue(
      new ApiError(
        'This finding already has the analytic local-first. Open it in the Analytics tab.',
        409,
        'analytic_exists_for_finding',
      ),
    );
    mount();
    await screen.findByText(threat.title);
    fireEvent.click(screen.getByRole('button', { name: /draft an analytic/i }));
    expect(await screen.findByRole('link', { name: 'local-first' })).toBeInTheDocument();
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
      ...PREVIEW,
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

  // The owner's case: the draft named one host and two domains. The confirm
  // warns above the dry run and the save says what it does.
  it('warns that a pinned draft is specific to one case and reads "Save anyway"', async () => {
    const pin =
      'The clause on dns.query.name pins the analytic to a fixed list of domain values. Describe the behaviour.';
    vi.mocked(getHunt).mockResolvedValue(huntFixture([threat]));
    vi.mocked(draftAnalytic)
      .mockResolvedValueOnce({
        ...PREVIEW,
        generalization: { pinned: [pin], retried: true },
        dry_run: { ...PREVIEW.dry_run, entity_count: 1, scope_kind: 'host' },
      })
      .mockResolvedValueOnce(DRAFT);
    mount();
    await screen.findByText(threat.title);
    fireEvent.click(screen.getByRole('button', { name: /draft an analytic/i }));

    const pins = await screen.findByTestId('draft-analytic-pins');
    expect(pins.textContent).toContain('This analytic is specific to one case.');
    expect(pins.textContent).toContain(pin);
    const dialog = screen.getByRole('dialog');
    // The warning sits above the dry run.
    expect(dialog.textContent!.indexOf(pin)).toBeLessThan(
      dialog.textContent!.indexOf('Dry run over 30 days'),
    );
    expect(dialog.textContent).toContain('Dry run over 30 days: 3 matches. 1 host matched in 30 days.');
    expect(screen.queryByRole('button', { name: /save candidate/i })).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Save anyway' }));
    await waitFor(() =>
      expect(draftAnalytic).toHaveBeenLastCalledWith(HUNT_ID, 0, {
        specYaml: PREVIEW.spec_yaml,
        retried: true,
      }),
    );
  });

  it('shows no warning for a draft that describes a behaviour', async () => {
    vi.mocked(getHunt).mockResolvedValue(huntFixture([threat]));
    vi.mocked(draftAnalytic).mockResolvedValue({
      ...PREVIEW,
      generalization: null,
      dry_run: { ...PREVIEW.dry_run, entity_count: 4, scope_kind: 'ip' },
    });
    mount();
    await screen.findByText(threat.title);
    fireEvent.click(screen.getByRole('button', { name: /draft an analytic/i }));

    const dialog = await screen.findByRole('dialog');
    expect(screen.queryByTestId('draft-analytic-pins')).toBeNull();
    expect(dialog.textContent).toContain('4 addresses matched in 30 days.');
    expect(screen.getByRole('button', { name: /save candidate/i })).toBeTruthy();
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
    expect(line.textContent).toBe('The hunt ended in an error. The server recorded no reason.');
  });

  // RH7: a cancelled hunt wore INCONCLUSIVE beside "Cancelled", said "The hunt
  // failed. No reason was recorded.", then "A cancel request stopped this
  // hunt", then "No findings yet." A stopped hunt says one thing once.
  it.each([
    ['cancelled', 'A cancel request stopped this hunt before it finished.'],
    ['interrupted', 'A service restart stopped this hunt before it finished.'],
  ] as const)('a %s hunt says why once, and never "yet"', async (status, sentence) => {
    vi.mocked(getHunt).mockResolvedValue({ ...errored(''), status });
    mount();
    const line = await screen.findByTestId('hunt-failure-reason');
    expect(line.textContent).toBe(sentence);
    expect(screen.queryByTestId('hunt-disposition')).toBeNull();
    expect(screen.queryByText(/No findings yet/)).toBeNull();
    expect(screen.queryByText(/failed/i)).toBeNull();
    expect(screen.getByText('The hunt stopped before it recorded a finding.')).toBeInTheDocument();
    expect(screen.getAllByText(/stopped this hunt/)).toHaveLength(1);
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

// F14, RH13: /app/hunts/<bogus id> polled GET every 3 s, a 404 each time, for
// as long as the tab stayed open. A 404 is an answer.
describe('HuntDetail stops polling a hunt that does not exist', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about);
  });

  it('asks once and shows the not-found card', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      vi.mocked(getHunt).mockRejectedValue(new ApiError('not found', 404, 'not_found'));
      mount();
      await screen.findByText(/Back to Hunt Console/);
      await vi.advanceTimersByTimeAsync(10_000);
      expect(getHunt).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('keeps polling a running hunt', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      vi.mocked(getHunt).mockResolvedValue({ ...huntFixture([]), status: 'running' });
      mount();
      await screen.findByText('No findings yet.');
      await vi.advanceTimersByTimeAsync(7_000);
      expect(vi.mocked(getHunt).mock.calls.length).toBeGreaterThan(1);
    } finally {
      vi.useRealTimers();
    }
  });
});
