// Prod, 2026-11-03, hunt 01M6HB9Y7JDA71ZEYME4N2MSF2: 36 model responses with no
// reasoning trace, 3 false threat findings, and a page that read "Complete".
// Prod, 2026-10-31, hunt 01M69M3FVK9D6KECGCAXJK9F6Z: the page of a lost hunt
// read "UsageLimitExceeded ... tool_calls_limit of 0 (tool_calls=2)" in its
// first line.
//
// A hunt that completed in a degraded state wears a mark and states it. A lost
// hunt states a plain cause, and the raw error opens on a click.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AboutInfo, HuntDetailData } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunt: vi.fn(),
  getHunts: vi.fn().mockResolvedValue([]),
  getLead: vi.fn(),
  promoteFinding: vi.fn(),
  getHuntChat: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  postHuntChat: vi.fn(),
  getAbout: vi.fn(),
}));

import { getAbout, getHunt } from '../lib/api';
import { HuntDetail } from './HuntDetail';

const about: AboutInfo = {
  version: '1.0.0',
  repo_url: 'https://example.test/soc-ai',
  license: 'MIT',
  update_check_enabled: false,
  general_chat_enabled: true,
  sigma_authoring_enabled: false,
};

const NOTE =
  'The model returned no reasoning trace in this hunt. Earlier hunts carried one. ' +
  'Check each finding against its evidence.';
const FINDING_NOTE =
  'degraded run: the model returned no reasoning trace in this hunt. ' +
  'Check this finding against its evidence before you act.';
const CAUSE =
  'The hunt reached its budget before it wrote a report. The model then answered with a ' +
  'tool call and wrote no report. The trace shows what the hunt read. Hunt again.';
const RAW =
  'UsageLimitExceeded: hunt hit its budget and partial synthesis failed: The next tool ' +
  'call(s) would exceed the tool_calls_limit of 0 (tool_calls=2).';

function hunt(over: Partial<HuntDetailData>): HuntDetailData {
  return {
    id: 'H-1',
    objective: 'Hunt for malicious activity over the past 72 hours.',
    kind: 'scheduled',
    status: 'complete',
    narrative: 'Suspicious: one host beacons to a listed address.',
    findings: [
      {
        title: 'Host beacons to a listed address',
        detail: 'The flows are periodic.',
        severity: 'medium',
        category: 'threat',
        hosts: ['192.0.2.10'],
        citations: [],
        validatorNote: FINDING_NOTE,
      },
    ],
    affectedHosts: ['192.0.2.10'],
    mitreTechniques: [],
    recommendedActions: [],
    confidence: 0.7,
    startedBy: 'scheduler',
    elapsedLabel: '56m 50s',
    elapsedSec: 3410,
    ts: '2026-11-03T18:38:51Z',
    timeline: [],
    diff: null,
    outcome: 'threat_found',
    outcome_label: 'Threat found',
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

describe('HuntDetail degraded run', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about);
  });

  it('wears the Degraded chip and states the reason', async () => {
    vi.mocked(getHunt).mockResolvedValue(
      hunt({ degraded: 'no_reasoning_trace', degradedNote: NOTE }),
    );
    mount();
    const chip = await screen.findByTestId('hunt-degraded');
    expect(chip.textContent).toBe('Degraded');
    expect(chip.getAttribute('title')).toBe(NOTE);
    expect(screen.getByTestId('hunt-degraded-note').textContent).toBe(NOTE);
    // The finding states the mark too.
    expect(screen.getByText(FINDING_NOTE)).toBeInTheDocument();
  });

  it('shows no mark on a hunt that carries none', async () => {
    vi.mocked(getHunt).mockResolvedValue(
      hunt({ findings: [], degraded: null, degradedNote: null }),
    );
    mount();
    await screen.findByTestId('hunt-title');
    expect(screen.queryByTestId('hunt-degraded')).toBeNull();
    expect(screen.queryByTestId('hunt-degraded-note')).toBeNull();
  });

  it('shows no mark for a server that sends no field', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt({ findings: [] }));
    mount();
    await screen.findByTestId('hunt-title');
    expect(screen.queryByTestId('hunt-degraded')).toBeNull();
  });
});

describe('HuntDetail lost hunt', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about);
  });

  const lost = (over: Partial<HuntDetailData> = {}): HuntDetailData =>
    hunt({
      status: 'error',
      narrative: CAUSE,
      findings: [],
      confidence: null,
      outcome: 'could_not_run',
      outcome_label: 'Could not run',
      outcome_headline: CAUSE,
      errorDetail: RAW,
      ...over,
    });

  it('states the plain cause and keeps the raw error behind a toggle', async () => {
    vi.mocked(getHunt).mockResolvedValue(lost());
    mount();
    const reason = await screen.findByTestId('hunt-failure-reason');
    expect(reason.textContent).toBe(CAUSE);
    // The raw error is not on the page until the analyst asks for it.
    expect(screen.queryByTestId('hunt-error-detail')).toBeNull();
    expect(document.body.textContent).not.toContain('tool_calls_limit');
    expect(document.body.textContent).not.toContain('UsageLimitExceeded');

    const toggle = screen.getByTestId('hunt-error-detail-toggle');
    expect(toggle.textContent).toBe('Show the technical detail');
    fireEvent.click(toggle);
    expect(screen.getByTestId('hunt-error-detail').textContent).toBe(RAW);
    expect(toggle.textContent).toBe('Hide the technical detail');
    fireEvent.click(toggle);
    expect(screen.queryByTestId('hunt-error-detail')).toBeNull();
  });

  it('offers no toggle when the server stored no error', async () => {
    vi.mocked(getHunt).mockResolvedValue(lost({ errorDetail: null }));
    mount();
    await screen.findByTestId('hunt-failure-reason');
    expect(screen.queryByTestId('hunt-error-detail-toggle')).toBeNull();
  });

  it('offers no toggle on a hunt that completed', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt({ findings: [] }));
    mount();
    await screen.findByTestId('hunt-title');
    expect(screen.queryByTestId('hunt-error-detail-toggle')).toBeNull();
  });
});
