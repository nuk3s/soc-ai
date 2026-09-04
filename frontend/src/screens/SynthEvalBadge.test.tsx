// Quality spine — the synthetic-evaluation marker is DISPLAYED, not just
// persisted. A hunt run against planted synthetic attack scenarios (and any
// investigation promoted from it) carries is_synth_eval in the store since
// migration 0032; these tests pin that the flag reaches every surface a hunt
// or investigation is listed or opened on, as a plain-English badge an analyst
// cannot mistake ("Synthetic — evaluation data" — never internal vocabulary).
// Both directions are pinned per surface: flag true renders the badge, flag
// false renders no badge at all.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DemoProvider } from '../lib/demo';
import type {
  HuntDetailData,
  HuntRow,
  Investigation as Inv,
  InvestigationList,
  InvestigationRow,
  Notification,
} from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  // Hunts list
  getHunts: vi.fn(),
  getHuntStats: vi.fn().mockResolvedValue([]),
  getHuntTemplates: vi.fn().mockResolvedValue([]),
  getHuntSchedules: vi.fn().mockResolvedValue({ schedules: [], masterSwitchEnabled: true }),
  // Hunt detail
  getHunt: vi.fn(),
  getHuntChat: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getAbout: vi.fn().mockResolvedValue({
    version: '1.0.0',
    repo_url: 'https://example.test/soc-ai',
    license: 'MIT',
    update_check_enabled: false,
    general_chat_enabled: true,
    sigma_authoring_enabled: false,
  }),
  // Investigations list
  listInvestigations: vi.fn(),
  listSavedViews: vi.fn().mockResolvedValue([]),
  // Investigation detail
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  // Notifications (screen + Topbar bell)
  getNotifications: vi.fn(),
  getWorkspaces: vi.fn().mockResolvedValue([]),
  getHealth: vi.fn().mockResolvedValue(null),
  // Dashboard
  getAlerts: vi.fn().mockResolvedValue([]),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getDetectionTuningSummary: vi.fn().mockResolvedValue(null),
  getGeneralChat: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getPreflight: vi.fn().mockResolvedValue({
    status: 'green',
    failing: 0,
    warned: 0,
    checked_at: '2026-08-26T00:00:00+00:00',
  }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-08-26T00:00:00+00:00' }),
  startQualityEval: vi.fn(),
  // Redaction preview picker
  getInvestigations: vi.fn(),
  getRedactionPreview: vi.fn().mockResolvedValue({
    original: {},
    sanitized: {},
    summary: {},
    replacements: [],
    note: '',
  }),
}));

import { getHunt, getHunts, getInvestigations, getNotifications, listInvestigations } from '../lib/api';
import { ShellProvider } from '../shell/ShellContext';
import { Topbar } from '../shell/Topbar';
import { Dashboard } from './Dashboard';
import { HuntDetail } from './HuntDetail';
import { Hunts } from './Hunts';
import { Investigation } from './Investigation';
import { Investigations } from './Investigations';
import { Notifications } from './Notifications';
import { RedactionPreviewPanel } from './RedactionPreviewPanel';

const BADGE = 'Synthetic — evaluation data';

const huntRow = (over: Partial<HuntRow>): HuntRow => ({
  id: 'H-1',
  objective: 'sweep for regular-cadence beaconing',
  kind: 'chat',
  status: 'complete',
  findingCount: 1,
  affectedHosts: 1,
  confidence: 0.7,
  startedBy: 'eval',
  when: '2h ago',
  ts: '2026-08-26T00:00:00+00:00',
  ...over,
});

const huntDetail = (over: Partial<HuntDetailData>): HuntDetailData => ({
  id: 'H-1',
  objective: 'sweep for regular-cadence beaconing',
  kind: 'chat',
  status: 'complete',
  narrative: 'One beaconing pair surfaced.',
  findings: [],
  affectedHosts: [],
  mitreTechniques: [],
  recommendedActions: [],
  confidence: 0.7,
  startedBy: 'eval',
  elapsedLabel: '2m 10s',
  elapsedSec: 130,
  ts: '2026-08-26T00:00:00+00:00',
  timeline: [],
  diff: null,
  ...over,
});

const invRow = (over: Partial<InvestigationRow>): InvestigationRow => ({
  id: 'INV-1',
  name: 'Planted C2 beacon',
  kind: 'suricata',
  verdict: 'true_positive',
  conf: 0.9,
  host: '10.0.0.115',
  dst: '104.18.42.69',
  status: 'complete',
  when: '2h ago',
  ts: '2026-08-26T00:00:00+00:00',
  alertId: 'ev-1',
  isPrimary: true,
  fallback: false,
  ...over,
});

const invList = (rows: InvestigationRow[]): InvestigationList => ({
  rows,
  total: rows.length,
  running: 0,
  truePositives: 0,
  totalAll: rows.length,
  active: false,
  limit: 50,
  offset: 0,
});

const invDetail = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'Planted C2 beacon',
    kind: 'suricata',
    host: '10.0.0.115',
    ip: '104.18.42.69',
    verdict: 'true_positive',
    conf: 0.9,
    rationale: 'JA3 pair + beacon cadence.',
    summary: [{ t: 'text', v: 'beacon' }],
    status: 'complete',
    elapsedLabel: '4m 5s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

const mountHunts = () =>
  render(
    <MemoryRouter initialEntries={['/hunts']}>
      <DemoProvider demo={false}>
        <Routes>
          <Route path="/hunts" element={<Hunts />} />
        </Routes>
      </DemoProvider>
    </MemoryRouter>,
  );

const mountHuntDetail = () =>
  render(
    <MemoryRouter initialEntries={['/hunts/H-1']}>
      <Routes>
        <Route path="/hunts/:id" element={<HuntDetail />} />
      </Routes>
    </MemoryRouter>,
  );

const mountInvestigations = () =>
  render(
    <MemoryRouter initialEntries={['/investigations']}>
      <Investigations />
    </MemoryRouter>,
  );

const mountInvestigation = (inv: Inv) =>
  render(
    <MemoryRouter>
      <Investigation inv={inv} layout="page" />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getHunts).mockResolvedValue([]);
  vi.mocked(listInvestigations).mockResolvedValue(invList([]));
  vi.mocked(getNotifications).mockResolvedValue([]);
  vi.mocked(getInvestigations).mockResolvedValue([]);
});

describe('Hunts list — synthetic-evaluation badge', () => {
  it('badges a synth-eval hunt row', async () => {
    vi.mocked(getHunts).mockResolvedValue([huntRow({ isSynthEval: true })]);
    mountHunts();
    await screen.findByText('sweep for regular-cadence beaconing');
    expect(screen.getByText(BADGE)).toBeInTheDocument();
  });

  it('shows no badge on an ordinary hunt row', async () => {
    vi.mocked(getHunts).mockResolvedValue([huntRow({ isSynthEval: false })]);
    mountHunts();
    await screen.findByText('sweep for regular-cadence beaconing');
    expect(screen.queryByText(BADGE)).toBeNull();
  });
});

describe('Hunt detail — synthetic-evaluation badge', () => {
  it('badges a synth-eval hunt', async () => {
    vi.mocked(getHunt).mockResolvedValue(huntDetail({ isSynthEval: true }));
    mountHuntDetail();
    await screen.findAllByText(/regular-cadence beaconing/);
    expect(screen.getByText(BADGE)).toBeInTheDocument();
  });

  it('shows no badge on an ordinary hunt', async () => {
    vi.mocked(getHunt).mockResolvedValue(huntDetail({ isSynthEval: false }));
    mountHuntDetail();
    await screen.findAllByText(/regular-cadence beaconing/);
    expect(screen.queryByText(BADGE)).toBeNull();
  });
});

describe('Investigations list — synthetic-evaluation badge', () => {
  it('badges a synth-eval investigation row', async () => {
    vi.mocked(listInvestigations).mockResolvedValue(invList([invRow({ isSynthEval: true })]));
    mountInvestigations();
    await screen.findByText('Planted C2 beacon');
    expect(screen.getByText(BADGE)).toBeInTheDocument();
  });

  it('shows no badge on an ordinary investigation row', async () => {
    vi.mocked(listInvestigations).mockResolvedValue(invList([invRow({ isSynthEval: false })]));
    mountInvestigations();
    await screen.findByText('Planted C2 beacon');
    expect(screen.queryByText(BADGE)).toBeNull();
  });
});

describe('Investigation detail — synthetic-evaluation badge', () => {
  it('badges a synth-eval investigation', () => {
    mountInvestigation(invDetail({ isSynthEval: true }));
    expect(screen.getByText(BADGE)).toBeInTheDocument();
  });

  it('shows no badge on an ordinary investigation', () => {
    mountInvestigation(invDetail({ isSynthEval: false }));
    expect(screen.queryByText(BADGE)).toBeNull();
  });
});

// ── Badge-coverage review (2026-08): the surfaces the first pass missed ──────
// The five suites above pinned the surfaces the branch badged. An adversarial
// review then found marked rows rendering bare on six more; each gets the same
// two-direction pin here. The Entity timeline is deliberately absent: synth
// rows are EXCLUDED from that read-model at the query (see
// test_entity_timeline_excludes_synth_eval_rows in tests/test_quality_spine.py),
// so there is no row there to badge.

const notif = (over: Partial<Notification>): Notification => ({
  id: 'inv-done:INV-1',
  tone: 'danger',
  title: 'Verdict true_positive: Planted C2 beacon',
  when: '2h',
  href: '/investigation/INV-1',
  ...over,
});

describe('Notifications screen — synthetic-evaluation badge', () => {
  const mountNotifications = () =>
    render(
      <MemoryRouter>
        <Notifications />
      </MemoryRouter>,
    );

  it('badges a synth-eval notification row', async () => {
    vi.mocked(getNotifications).mockResolvedValue([notif({ isSynthEval: true })]);
    mountNotifications();
    await screen.findByText(/Planted C2 beacon/);
    expect(screen.getByText(BADGE)).toBeInTheDocument();
  });

  it('shows no badge on an ordinary notification row', async () => {
    vi.mocked(getNotifications).mockResolvedValue([notif({ isSynthEval: false })]);
    mountNotifications();
    await screen.findByText(/Planted C2 beacon/);
    expect(screen.queryByText(BADGE)).toBeNull();
  });
});

describe('Topbar bell dropdown — synthetic-evaluation badge', () => {
  const mountTopbar = () =>
    render(
      <MemoryRouter>
        <ShellProvider>
          <Topbar />
        </ShellProvider>
      </MemoryRouter>,
    );

  it('badges a synth-eval item in the dropdown', async () => {
    vi.mocked(getNotifications).mockResolvedValue([notif({ isSynthEval: true })]);
    mountTopbar();
    fireEvent.click(await screen.findByLabelText('Notifications'));
    await screen.findByText(/Planted C2 beacon/);
    expect(screen.getByText(BADGE)).toBeInTheDocument();
  });

  it('shows no badge on an ordinary item', async () => {
    vi.mocked(getNotifications).mockResolvedValue([notif({ isSynthEval: false })]);
    mountTopbar();
    fireEvent.click(await screen.findByLabelText('Notifications'));
    await screen.findByText(/Planted C2 beacon/);
    expect(screen.queryByText(BADGE)).toBeNull();
  });
});

describe('Investigation failed states — synthetic-evaluation badge', () => {
  // The badge used to live only inside the verdict card, so a synthetic run
  // that ended error / cancelled / interrupted rendered the failure panel with
  // no marker at all — the failure headline is asserted first so each test
  // proves it is exercising the failed branch, not the verdict card.
  it('keeps the badge on an errored run', () => {
    mountInvestigation(invDetail({ isSynthEval: true, status: 'error' }));
    screen.getByText('This investigation failed or was interrupted');
    expect(screen.getByText(BADGE)).toBeInTheDocument();
  });

  it('keeps the badge on a cancelled run', () => {
    mountInvestigation(invDetail({ isSynthEval: true, status: 'cancelled' }));
    screen.getByText('This investigation was cancelled before it finished');
    expect(screen.getByText(BADGE)).toBeInTheDocument();
  });

  it('keeps the badge on an interrupted run', () => {
    mountInvestigation(invDetail({ isSynthEval: true, status: 'interrupted' }));
    screen.getByText('This investigation was interrupted by a restart');
    expect(screen.getByText(BADGE)).toBeInTheDocument();
  });

  it('shows no badge on an ordinary errored run', () => {
    mountInvestigation(invDetail({ isSynthEval: false, status: 'error' }));
    screen.getByText('This investigation failed or was interrupted');
    expect(screen.queryByText(BADGE)).toBeNull();
  });
});

describe('Dashboard recent investigations — synthetic-evaluation badge', () => {
  const mountDashboard = () =>
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );

  it('badges a synth-eval row', async () => {
    vi.mocked(listInvestigations).mockResolvedValue(invList([invRow({ isSynthEval: true })]));
    mountDashboard();
    await screen.findByText('Planted C2 beacon');
    expect(screen.getByText(BADGE)).toBeInTheDocument();
  });

  it('shows no badge on an ordinary row', async () => {
    vi.mocked(listInvestigations).mockResolvedValue(invList([invRow({ isSynthEval: false })]));
    mountDashboard();
    await screen.findByText('Planted C2 beacon');
    expect(screen.queryByText(BADGE)).toBeNull();
  });
});

describe('Redaction preview picker — synthetic-evaluation badge', () => {
  // <option> can hold text only, so the marker is the badge's exact wording
  // appended to the label rather than the component.
  it('marks a synth-eval run in the option label', async () => {
    vi.mocked(getInvestigations).mockResolvedValue([invRow({ isSynthEval: true })]);
    render(<RedactionPreviewPanel />);
    fireEvent.click(screen.getByRole('tab', { name: 'Analyst path' }));
    const option = await screen.findByRole('option', { name: /Planted C2 beacon/ });
    expect(option.textContent).toContain(BADGE);
  });

  it('adds no marker to an ordinary run', async () => {
    vi.mocked(getInvestigations).mockResolvedValue([invRow({ isSynthEval: false })]);
    render(<RedactionPreviewPanel />);
    fireEvent.click(screen.getByRole('tab', { name: 'Analyst path' }));
    const option = await screen.findByRole('option', { name: /Planted C2 beacon/ });
    expect(option.textContent).not.toContain('Synthetic');
  });
});
