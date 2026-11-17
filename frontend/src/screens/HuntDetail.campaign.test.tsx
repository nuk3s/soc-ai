// A finding that restates a campaign gets no investigation of its own
// (recommendation 7, 2026-11-16). Its card says that the campaign holds it,
// with the chip of the campaign. The header of a campaign hunt names its
// campaign.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AboutInfo, HuntDetailData, HuntFinding } from '../lib/types';

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
import { forbiddenWords } from '../test/analystWords';
import { LINK } from '../test/campaign';
import { HuntDetail, LeadDecisionBar, findingHeldByCampaign, starterWords } from './HuntDetail';

const about: AboutInfo = {
  version: '1.0.0',
  repo_url: 'https://example.test/soc-ai',
  license: 'MIT',
  update_check_enabled: false,
  general_chat_enabled: true,
  sigma_authoring_enabled: false,
};

function finding(title: string, over: Partial<HuntFinding>): HuntFinding {
  return {
    title,
    detail: `${title}. The detail.`,
    severity: 'high',
    category: 'threat',
    hosts: ['192.0.2.10', '192.0.2.20'],
    citations: ['doc-3'],
    ...over,
  };
}

const HELD_WORDS =
  'Held by the campaign actor-a against web-1: no new stage, no new machine, no later event.';

const held = finding('actor-a reads a file on web-1 through the web shell', {
  investigationStatus: 'campaign',
  campaign: LINK,
});

const own = finding('web-1 connects to a third machine', {
  investigationId: 'inv-own',
  investigation: { id: 'inv-own', status: 'complete', verdict: 'true_positive', conf: 0.85 },
  investigationStatus: 'complete',
  investigationOrigin: 'opened',
  verdict: 'true_positive',
  confidence: 0.85,
});

function hunt(over: Partial<HuntDetailData> = {}): HuntDetailData {
  return {
    id: 'H-1',
    objective: 'Hunt for malicious activity over the past 24 hours.',
    kind: 'scheduled',
    status: 'complete',
    narrative: 'The campaign actor-a against web-1 continues. One machine is new.',
    findings: [held, own],
    affectedHosts: ['192.0.2.20'],
    mitreTechniques: [],
    recommendedActions: [],
    confidence: 0.7,
    startedBy: 'scheduler',
    starter: 'schedule',
    elapsedLabel: '5m 2s',
    elapsedSec: 302,
    ts: '2026-11-14T18:40:00Z',
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

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getAbout).mockResolvedValue(about);
});

describe('a finding that a campaign holds', () => {
  it('reads the sentence of the campaign with the chip, and asks for no investigation', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt());
    mount();
    await screen.findByText(held.title);
    const c = card(held.title);
    const line = within(c).getByTestId('finding-held');
    expect(line).toHaveTextContent(HELD_WORDS);
    expect(within(line).getByTestId('finding-campaign')).toHaveAttribute('href', '/campaigns/7');
    // No line of an investigation that waits, and no verdict.
    expect(within(c).queryByTestId('finding-investigation')).toBeNull();
    expect(c.textContent).not.toMatch(/waits for a free slot|reached no verdict|re-run/i);
    // The manual control stays, and it is no call to act.
    const open = within(c).getByRole('button', { name: /Open an investigation/ });
    expect(open).toHaveAttribute('data-quiet', 'true');
    // The words this change adds. The card keeps "run" as a verb of a hunt elsewhere.
    expect([...forbiddenWords(line), ...forbiddenWords(open)]).toEqual([]);
  });

  it('NEGATIVE CONTROL: a finding with its own investigation keeps its verdict line', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt());
    mount();
    await screen.findByText(own.title);
    const c = card(own.title);
    expect(within(c).queryByTestId('finding-held')).toBeNull();
    expect(within(c).getByTestId('finding-verdict')).toHaveTextContent('True positive');
  });

  it('reads a held finding from the campaign field when the state is absent', () => {
    expect(findingHeldByCampaign({ ...held, investigationStatus: null })).toEqual(LINK);
    // NEGATIVE CONTROL: the campaign of an investigation does not hold the finding.
    expect(findingHeldByCampaign({ ...own, campaign: LINK })).toBeNull();
    expect(findingHeldByCampaign({ ...held, campaign: null })).toBeNull();
  });
});

describe('the header of a hunt of a campaign', () => {
  it('names the campaign that a campaign hunt answers', async () => {
    vi.mocked(getHunt).mockResolvedValue(
      hunt({ kind: 'triggered', starter: 'campaign', startedBy: 'campaign-hunt', campaign: LINK }),
    );
    mount();
    const line = await screen.findByTestId('hunt-campaign');
    expect(line).toHaveTextContent('soc-ai started this hunt on a change of the campaign actor-a against web-1.');
    expect(within(line).getByRole('link', { name: 'actor-a against web-1' })).toHaveAttribute('href', '/campaigns/7');
    expect(screen.getByTestId('hunt-campaign-chip')).toHaveAttribute('href', '/campaigns/7');
    expect(starterWords('campaign-hunt')).toBe('soc-ai');
    // The flow starts at the campaign. The stored kind of the hunt is no starter.
    expect(screen.getByTestId('flow-step-campaign')).toHaveAttribute('data-state', 'done');
    expect(screen.queryByTestId('flow-step-analytic')).toBeNull();
  });

  it('names the campaign of a lead hunt that the campaign holds', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt({ kind: 'lead', starter: 'lead', campaign: LINK }));
    mount();
    expect(await screen.findByTestId('hunt-campaign')).toHaveTextContent(
      'This hunt is part of the campaign actor-a against web-1.',
    );
  });

  it('NEGATIVE CONTROL: a hunt of no campaign names none', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt({ findings: [own] }));
    mount();
    await screen.findByText(own.title);
    expect(screen.queryByTestId('hunt-campaign')).toBeNull();
    expect(screen.queryByTestId('hunt-campaign-chip')).toBeNull();
  });
});

describe('the lead decision bar of a lead of a campaign', () => {
  const bar = (campaign: typeof LINK | null) =>
    render(
      <MemoryRouter>
        <LeadDecisionBar lead={{ id: 4, status: 'hunting', dismiss_reasons: [], campaign }} onChanged={() => {}} />
      </MemoryRouter>,
    );

  it('names the campaign and does not say that the lead waits', () => {
    bar(LINK);
    const region = screen.getByTestId('hunt-lead-decision');
    expect(region).toHaveAttribute('data-held', 'true');
    expect(region).toHaveTextContent('Part of the campaign actor-a against web-1. Decide on the campaign.');
    expect(region.textContent).not.toMatch(/waits on you/);
    expect(within(region).getByTestId('hunt-lead-campaign')).toHaveAttribute('href', '/campaigns/7');
  });

  it('NEGATIVE CONTROL: a lead of no campaign waits on the analyst', () => {
    bar(null);
    expect(screen.getByTestId('hunt-lead-decision')).toHaveTextContent('Lead 4 waits on you.');
  });
});
