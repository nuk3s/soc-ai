// A hunt investigates its subject findings as part of the hunt (2026-10-07).
// The findings section states the progress while the investigations run, and
// each finding card states its investigation: the verdict, the confidence
// word, the actions that wait and the link, or the reason it has none. The
// manual control stays on a finding with no investigation.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AboutInfo, HuntDetailData, HuntFinding } from '../lib/types';

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
  getHunts: vi.fn(),
  getLead: vi.fn(),
  getEvent: vi.fn(),
}));

import { getAbout, getHunt } from '../lib/api';
import {
  HuntDetail,
  findingInvestigationStatus,
  findingsProgressLine,
  pendingActionsText,
  sharedInvestigationText,
} from './HuntDetail';

const about: AboutInfo = {
  version: '1.0.0',
  repo_url: 'https://example.test/soc-ai',
  license: 'MIT',
  update_check_enabled: false,
  general_chat_enabled: true,
  sigma_authoring_enabled: false,
};

function finding(n: number, over: Partial<HuntFinding> = {}): HuntFinding {
  return {
    title: `Beacon from host ${n}`,
    detail: `Host 10.0.0.${n} calls out on a fixed cadence.`,
    severity: 'high',
    category: 'threat',
    hosts: [`10.0.0.${n}`],
    citations: [`tel-doc-0000000${n}`],
    ...over,
  };
}

const confirmed = finding(1, {
  investigationId: 'inv-tp',
  investigation: { id: 'inv-tp', status: 'complete', verdict: 'true_positive', conf: 0.86 },
  investigationStatus: 'complete',
  verdict: 'true_positive',
  confidence: 0.86,
  pendingActions: 2,
});
const cleared = finding(2, {
  investigationId: 'inv-fp',
  investigation: { id: 'inv-fp', status: 'complete', verdict: 'false_positive', conf: 0.74 },
  investigationStatus: 'complete',
  verdict: 'false_positive',
  confidence: 0.74,
  pendingActions: 0,
});
const failed = finding(3, {
  investigationId: 'inv-err',
  investigation: { id: 'inv-err', status: 'error', verdict: null, conf: null },
  investigationStatus: 'failed',
});
const overCap = finding(4, { investigationStatus: 'over_cap' });
const queued = finding(5, { investigationStatus: 'queued' });
const running = finding(6, {
  investigationId: 'inv-run',
  investigation: { id: 'inv-run', status: 'running', verdict: null, conf: null },
  investigationStatus: 'running',
});
const gap = finding(7, { category: 'visibility_gap', title: 'No process telemetry on ws-17' });

function hunt(over: Partial<HuntDetailData>): HuntDetailData {
  return {
    id: 'H-1',
    objective: 'hunt for beacons',
    kind: 'chat',
    status: 'complete',
    narrative: '',
    findings: [],
    affectedHosts: [],
    mitreTechniques: [],
    recommendedActions: [],
    confidence: 0.7,
    startedBy: 'analyst',
    elapsedLabel: '2m 10s',
    elapsedSec: 130,
    ts: '2026-10-07T09:00:00Z',
    timeline: [],
    diff: null,
    ...over,
  };
}

function mount() {
  return render(
    <MemoryRouter initialEntries={['/hunts/H-1']}>
      <Routes>
        <Route path="/hunts/:id" element={<HuntDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

function card(title: string): HTMLElement {
  const heading = screen.getAllByText(title).find((el) => el.closest('.rounded-card'));
  const el = heading?.closest('.rounded-card') as HTMLElement | null;
  if (!el) throw new Error(`no card for ${title}`);
  return el;
}

// The manual control. Another change renames it, so both names count.
const MANUAL = /^(promote|open an investigation)$/i;

describe('HuntDetail findings, investigated by the hunt', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about);
  });

  it('shows the verdict, the confidence word, the pending actions and the link', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt({ findings: [confirmed, cleared] }));
    mount();
    await screen.findAllByText(confirmed.title);

    const tp = within(card(confirmed.title)).getByTestId('finding-investigation');
    expect(within(tp).getByTestId('finding-verdict').textContent).toContain('True positive');
    expect(within(tp).getByTestId('finding-verdict').textContent).toContain('0.86');
    expect(within(tp).getByTestId('finding-confidence').textContent).toBe('High confidence');
    expect(within(tp).getByTestId('finding-pending-actions').textContent).toBe('2 actions wait');
    expect(within(tp).getByTestId('finding-investigation-link').getAttribute('href')).toBe(
      '/investigation/inv-tp',
    );

    const fp = within(card(cleared.title)).getByTestId('finding-investigation');
    expect(within(fp).getByTestId('finding-verdict').textContent).toContain('False positive');
    expect(within(fp).getByTestId('finding-confidence').textContent).toBe('Medium confidence');
    expect(within(fp).getByTestId('finding-pending-actions').textContent).toBe('No action waits');
    // A finding with an investigation offers no manual control.
    expect(within(card(confirmed.title)).queryByRole('button', { name: MANUAL })).toBeNull();
  });

  it('states a failed run and a finding past the cap, and keeps the manual control', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt({ findings: [failed, overCap] }));
    mount();
    await screen.findAllByText(failed.title);

    const failedCard = card(failed.title);
    expect(within(failedCard).getByTestId('finding-investigation').textContent).toBe(
      'Investigation failed, re-run.',
    );
    expect(within(failedCard).getByRole('button', { name: MANUAL })).toBeTruthy();

    const capCard = card(overCap.title);
    expect(within(capCard).getByTestId('finding-investigation').textContent).toBe(
      'Over the cap, open by hand.',
    );
    expect(within(capCard).getByRole('button', { name: MANUAL })).toBeTruthy();
    expect(within(capCard).queryByTestId('finding-verdict')).toBeNull();
  });

  it('counts the investigations above the list while the phase runs', async () => {
    vi.mocked(getHunt).mockResolvedValue(
      hunt({
        status: 'investigating',
        outcome: 'investigating',
        findings: [confirmed, running, queued],
        findingsInvestigated: 1,
        findingsTotal: 3,
      }),
    );
    mount();
    expect((await screen.findByTestId('findings-progress')).textContent).toBe(
      'Investigating 1 of 3 findings',
    );
    expect(within(card(running.title)).getByTestId('finding-investigation').textContent).toContain(
      'The investigation runs.',
    );
    expect(within(card(queued.title)).getByTestId('finding-investigation').textContent).toBe(
      'The investigation waits for a free slot.',
    );
  });

  it('shows no progress line on a complete hunt and no line on a gap', async () => {
    vi.mocked(getHunt).mockResolvedValue(
      hunt({ findings: [confirmed, gap], findingsInvestigated: 1, findingsTotal: 1 }),
    );
    mount();
    await screen.findAllByText(confirmed.title);
    expect(screen.queryByTestId('findings-progress')).toBeNull();
    expect(within(card(gap.title)).queryByTestId('finding-investigation')).toBeNull();
  });
});

// R3-D4: the range hunt of lead 18 linked one investigation to F1 and F2,
// and each card read the verdict as its own.
describe('a shared investigation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about);
  });

  it('names the finding whose investigation a card shares', async () => {
    const run = {
      investigationId: 'inv-tp',
      investigationStatus: 'complete' as const,
      verdict: 'true_positive',
      confidence: 0.72,
      pendingActions: 1,
    };
    const first = finding(1, { ...run, sharedWith: [1], investigationSubject: 1 });
    const second = finding(2, { ...run, sharedWith: [0], investigationSubject: 1 });
    vi.mocked(getHunt).mockResolvedValue(hunt({ findings: [first, second, gap] }));
    mount();
    await screen.findAllByText(first.title);
    expect(within(card(first.title)).getByTestId('finding-shared-investigation').textContent).toBe(
      'Shares the investigation of F2.',
    );
    expect(within(card(second.title)).getByTestId('finding-shared-investigation').textContent).toBe(
      'F1 shares this investigation.',
    );
    // Control: the gap card has no investigation and no note.
    expect(within(card(gap.title)).queryByTestId('finding-shared-investigation')).toBeNull();
  });

  it('writes the note from the server fields', () => {
    const f = finding(1);
    expect(sharedInvestigationText(f, 0)).toBeNull();
    expect(sharedInvestigationText({ ...f, sharedWith: [], investigationSubject: 0 }, 0)).toBeNull();
    expect(sharedInvestigationText({ ...f, sharedWith: [1, 4], investigationSubject: 0 }, 0)).toBe(
      'F2 and F5 share this investigation.',
    );
    expect(sharedInvestigationText({ ...f, sharedWith: [0], investigationSubject: 0 }, 2)).toBe(
      'Shares the investigation of F1.',
    );
    expect(
      sharedInvestigationText({ ...f, investigationOrigin: 'reused', investigationSubject: null }, 0),
    ).toBe('Shares the investigation of an earlier hunt on the same subject.');
  });
});

describe('the finding investigation words', () => {
  it('reads the status an older server sends', () => {
    expect(findingInvestigationStatus(finding(1))).toBeNull();
    const legacy = finding(1, {
      investigation: { id: 'i', status: 'interrupted', verdict: null, conf: null },
    });
    expect(findingInvestigationStatus(legacy)).toBe('failed');
    expect(findingInvestigationStatus({ ...legacy, investigationStatus: 'complete' })).toBe(
      'complete',
    );
  });

  it('counts the pending actions in words', () => {
    expect(pendingActionsText(0)).toBe('No action waits');
    expect(pendingActionsText(1)).toBe('1 action waits');
    expect(pendingActionsText(3)).toBe('3 actions wait');
  });

  it('writes the progress line', () => {
    expect(findingsProgressLine({ findingsInvestigated: 2, findingsTotal: 3 })).toBe(
      'Investigating 2 of 3 findings',
    );
    expect(findingsProgressLine({ findingsInvestigated: 0, findingsTotal: 1 })).toBe(
      'Investigating 0 of 1 finding',
    );
  });
});
