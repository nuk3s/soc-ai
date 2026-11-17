// Prod, 2026-11-12, hunt 01M78GYGVKV84GA91CPWEW0QB9: the "vs last run" strip
// read "7 new · 0 persisting · 5 resolved" with "resolved" in green. Two of the
// five were the exploit of the day before, and it still ran. The comparison
// knows that this run did not report a finding. It does not know that the
// activity stopped. The count reads "not reported this run" in a neutral color.
import { fireEvent, render, screen, within } from '@testing-library/react';
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

const GREEN = 'rgb(63, 185, 80)';

function hunt(over: Partial<HuntDetailData>): HuntDetailData {
  return {
    id: 'H-1',
    objective: 'Hunt for malicious activity over the past 72 hours.',
    kind: 'scheduled',
    status: 'complete',
    narrative: 'The exploit of the day before continues.',
    findings: [],
    affectedHosts: [],
    mitreTechniques: [],
    recommendedActions: [],
    confidence: 0.7,
    startedBy: 'scheduler',
    elapsedLabel: '5m 2s',
    elapsedSec: 302,
    ts: '2026-11-12T18:40:00Z',
    timeline: [],
    diff: {
      new: [{ title: 'New external destination', severity: 'info', category: 'observation' }],
      persisting: [
        { title: 'php2shell exploit attempts hit the app', severity: 'high', category: 'threat' },
      ],
      notReported: [
        { title: 'Periodic flows are NTP', severity: 'info', category: 'observation' },
        { title: 'DNS entropy shows no DGA', severity: 'info', category: 'observation' },
      ],
      previousHuntId: 'H-0',
      previousTs: '2026-11-11T18:40:00Z',
      previousWhen: '1d ago',
    },
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

describe('HuntDetail vs last run', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about);
  });

  it('counts the findings this run did not report, and never calls them resolved', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt({}));
    mount();
    const strip = await screen.findByTestId('hunt-diff-strip');
    expect(strip.textContent).toContain('1new');
    expect(strip.textContent).toContain('1persisting');
    expect(strip.textContent).toContain('2not reported this run');
    expect(strip.textContent?.toLowerCase()).not.toContain('resolved');
  });

  it('shows the count in the neutral color of "persisting", not in green', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt({}));
    mount();
    const strip = await screen.findByTestId('hunt-diff-strip');
    const label = within(strip).getByText('not reported this run');
    const count = label.previousElementSibling as HTMLElement;
    const persisting = within(strip).getByText('persisting').previousElementSibling as HTMLElement;
    expect(count.textContent).toBe('2');
    expect(count.style.color).toBe(persisting.style.color);
    expect(count.style.color).not.toBe(GREEN);
    // Negative control: the "new" count keeps its own color.
    const fresh = within(strip).getByText('new').previousElementSibling as HTMLElement;
    expect(fresh.style.color).not.toBe(count.style.color);
  });

  it('lists the findings under "Not reported this run" with no green mark', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt({}));
    mount();
    const strip = await screen.findByTestId('hunt-diff-strip');
    fireEvent.click(within(strip).getByRole('button'));
    const heading = within(strip).getByText('Not reported this run');
    expect(heading.style.color).not.toBe(GREEN);
    expect(within(strip).getByText('Periodic flows are NTP')).toBeInTheDocument();
    expect(within(strip).getByText('DNS entropy shows no DGA')).toBeInTheDocument();
    expect(within(strip).queryByText(/resolved/i)).toBeNull();
  });

  it('opens the list when only not-reported findings exist', async () => {
    const base = hunt({});
    vi.mocked(getHunt).mockResolvedValue(
      hunt({ diff: { ...base.diff!, new: [], persisting: [] } }),
    );
    mount();
    const strip = await screen.findByTestId('hunt-diff-strip');
    fireEvent.click(within(strip).getByRole('button'));
    expect(within(strip).getByText('Not reported this run')).toBeInTheDocument();
  });
});
