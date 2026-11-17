// Prod, 2026-11-08 to 2026-11-12: one exploit became 12 threat findings and 12
// investigations in 5 scheduled hunts. A finding that names no new host and
// cites no new evidence now reads the investigation of the earlier finding.
// The card says so: "Restates <earlier finding>, verdict <x>".
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AboutInfo, HuntDetailData, HuntFinding } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunt: vi.fn(),
  getHunts: vi.fn().mockResolvedValue([]),
  getLead: vi.fn(),
  promoteFinding: vi.fn().mockResolvedValue({ investigation_id: 'inv-new' }),
  getHuntChat: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  postHuntChat: vi.fn(),
  getAbout: vi.fn(),
}));

import { getAbout, getHunt, promoteFinding } from '../lib/api';
import { HuntDetail, restatesText, sharedInvestigationText } from './HuntDetail';

const about: AboutInfo = {
  version: '1.0.0',
  repo_url: 'https://example.test/soc-ai',
  license: 'MIT',
  update_check_enabled: false,
  general_chat_enabled: true,
  sigma_authoring_enabled: false,
};

const EARLIER = 'LFI succeeds and leaks /proc/self/maps';

function finding(title: string, over: Partial<HuntFinding>): HuntFinding {
  return {
    title,
    detail: `${title}. The detail.`,
    severity: 'high',
    category: 'threat',
    hosts: ['192.0.2.164'],
    citations: [],
    ...over,
  };
}

const restated = finding('LFI on the app leaks /proc/self/maps', {
  investigationId: 'inv-earlier',
  investigation: { id: 'inv-earlier', status: 'complete', verdict: 'true_positive', conf: 0.8 },
  investigationStatus: 'complete',
  investigationOrigin: 'reused',
  verdict: 'true_positive',
  confidence: 0.8,
  restates: { huntId: 'H-0', ordinal: 1, title: EARLIER },
});

const own = finding('A new source exploits the app', {
  investigationId: 'inv-own',
  investigation: { id: 'inv-own', status: 'complete', verdict: 'true_positive', conf: 0.85 },
  investigationStatus: 'complete',
  investigationOrigin: 'opened',
  verdict: 'true_positive',
  confidence: 0.85,
});

function hunt(findings: HuntFinding[]): HuntDetailData {
  return {
    id: 'H-1',
    objective: 'Hunt for malicious activity over the past 72 hours.',
    kind: 'scheduled',
    status: 'complete',
    narrative: 'The exploit of the day before continues.',
    findings,
    affectedHosts: ['192.0.2.164'],
    mitreTechniques: [],
    recommendedActions: [],
    confidence: 0.7,
    startedBy: 'scheduler',
    elapsedLabel: '5m 2s',
    elapsedSec: 302,
    ts: '2026-11-12T18:40:00Z',
    timeline: [],
    diff: null,
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

describe('HuntDetail finding that restates an earlier finding', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about);
  });

  it('names the earlier finding and its verdict, and links to its hunt', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt([restated, own]));
    mount();
    await screen.findByText(restated.title);
    const note = within(card(restated.title)).getByTestId('finding-restates');
    expect(note.textContent).toBe(`Restates "${EARLIER}", verdict true positive.`);
    expect(note.getAttribute('href')).toBe('/hunts/H-0');
    // The verdict chip and the link to the investigation stay.
    expect(within(card(restated.title)).getByTestId('finding-verdict').textContent).toContain(
      'True positive',
    );
    expect(
      within(card(restated.title)).getByTestId('finding-investigation-link').getAttribute('href'),
    ).toBe('/investigation/inv-earlier');
    // One note: the older sentence for a reused run does not repeat it.
    expect(within(card(restated.title)).queryByTestId('finding-shared-investigation')).toBeNull();
  });

  it('shows no note on a finding with its own investigation', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt([restated, own]));
    mount();
    await screen.findByText(own.title);
    expect(within(card(own.title)).queryByTestId('finding-restates')).toBeNull();
  });

  it('names the earlier finding while its investigation still runs', async () => {
    const running: HuntFinding = {
      ...restated,
      investigation: { id: 'inv-earlier', status: 'running', verdict: null, conf: null },
      investigationStatus: 'running',
      verdict: null,
      confidence: null,
    };
    vi.mocked(getHunt).mockResolvedValue({ ...hunt([running]), status: 'investigating' });
    mount();
    await screen.findByText(running.title);
    expect(within(card(running.title)).getByTestId('finding-restates').textContent).toBe(
      `Restates "${EARLIER}".`,
    );
  });

  it('reads the live verdict of the earlier finding, not the stored one', async () => {
    // The earlier finding was overridden to a true positive at 0.9 after the hunt ran.
    const live: HuntFinding = {
      ...restated,
      verdict: 'true_positive',
      restates: { huntId: 'H-0', ordinal: 1, title: EARLIER, verdict: 'true_positive', answers: true },
    };
    vi.mocked(getHunt).mockResolvedValue(hunt([live]));
    mount();
    await screen.findByText(live.title);
    expect(within(card(live.title)).getByTestId('finding-restates').textContent).toBe(
      `Restates "${EARLIER}", verdict true positive.`,
    );
  });

  it('offers the finding its own investigation when the earlier verdict is no true positive', async () => {
    // A Re-run of the earlier finding ended needs more info. The server sends
    // no investigation for this finding, and the verdict of the latest run.
    const stale = finding('LFI on the app leaks /proc/self/maps', {
      citations: ['docAAAAAAAAAAAAAAAA2'],
      investigationId: null,
      investigation: null,
      investigationStatus: null,
      verdict: null,
      restates: {
        huntId: 'H-0',
        ordinal: 1,
        title: EARLIER,
        verdict: 'needs_more_info',
        answers: false,
      },
    });
    vi.mocked(getHunt).mockResolvedValue(hunt([stale]));
    mount();
    await screen.findByText(stale.title);
    const el = card(stale.title);
    const note = within(el).getByTestId('finding-restates-stale');
    expect(note.textContent).toContain(`Restates "${EARLIER}", verdict needs more info.`);
    expect(note.textContent).toContain('Open an investigation on this finding.');
    // No borrowed verdict, and the control that starts this finding's own run.
    expect(within(el).queryByTestId('finding-verdict')).toBeNull();
    const control = within(el).getByRole('button', { name: /open an investigation/i });
    fireEvent.click(control);
    await waitFor(() => expect(vi.mocked(promoteFinding)).toHaveBeenCalledWith('H-1', 0));
  });

  it('words each verdict, and keeps the older note for a plain reused run', () => {
    expect(restatesText({ ...restated, verdict: 'false_positive' })).toBe(
      `Restates "${EARLIER}", verdict false positive.`,
    );
    expect(restatesText({ ...restated, verdict: 'needs_more_info' })).toBe(
      `Restates "${EARLIER}", verdict needs more info.`,
    );
    expect(restatesText(own)).toBeNull();
    expect(sharedInvestigationText(restated, 0)).toBeNull();
    // Negative control: a run reused on the exact subject keeps its sentence.
    expect(sharedInvestigationText({ ...restated, restates: null }, 0)).toBe(
      'Shares the investigation of an earlier hunt on the same subject.',
    );
  });
});
