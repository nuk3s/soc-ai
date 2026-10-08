// The hunt page header cut the hunt's title at 80 characters with an ellipsis.
// The header has room, so the title now wraps and never cuts. A lead objective
// is a head sentence over a list of observations, and the header shows the
// head sentence whole.
import { render, screen } from '@testing-library/react';
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
import { TITLE_180, bareCuts, showsWhole } from '../test/wholeTitle';
import { HuntDetail } from './HuntDetail';

const about: AboutInfo = {
  version: '1.0.0',
  repo_url: 'https://example.test/soc-ai',
  license: 'MIT',
  update_check_enabled: false,
  general_chat_enabled: true,
  sigma_authoring_enabled: false,
};

function hunt(objective: string, over: Partial<HuntDetailData> = {}): HuntDetailData {
  return {
    id: 'H-1',
    objective,
    kind: 'chat',
    status: 'complete',
    narrative: '',
    findings: [],
    affectedHosts: [],
    mitreTechniques: [],
    recommendedActions: [],
    confidence: 0.72,
    startedBy: 'analyst',
    elapsedLabel: '2m 10s',
    elapsedSec: 130,
    ts: '2026-10-05T00:00:00Z',
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

describe('HuntDetail header keeps the whole hunt title', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about);
  });

  it('shows a 180 character title whole, with no ellipsis', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt(TITLE_180));
    mount();
    const title = await screen.findByTestId('hunt-title');
    // The leading imperative goes. Every other word stays.
    const expected = 'Internal hosts that beacon' + TITLE_180.slice('Hunt for internal hosts that beacon'.length);
    expect(title.textContent).toBe(expected);
    expect(title.textContent).not.toMatch(/…$/);
    expect(title.getAttribute('title')).toBe(TITLE_180);
    expect(title.className).not.toMatch(/\b(truncate|line-clamp-\d)\b/);
    expect(showsWhole(document.body, TITLE_180)).toBe(true);
    expect(bareCuts(document.body, TITLE_180)).toEqual([]);
  });

  it('shows the head sentence of a lead objective whole and keeps the list for the click', async () => {
    const head =
      '[lead 7] Investigate 192.0.2.10. The lead formed from a new destination and off hours and a collapsed rate on the weekend.';
    const objective = `${head}\nObservations:\n- first connection to 198.51.100.4\n- active at 03:00`;
    vi.mocked(getHunt).mockResolvedValue(hunt(objective, { kind: 'lead', starter: 'lead' }));
    mount();
    const title = await screen.findByTestId('hunt-title');
    expect(head.length).toBeGreaterThan(80);
    expect(title.textContent).toBe(head);
    expect(title.textContent).not.toContain('Observations');
    expect(title.getAttribute('title')).toBe(objective);
  });

  it('renders a short title unchanged', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt('hunt for service ticket abuse'));
    mount();
    const title = await screen.findByTestId('hunt-title');
    expect(title.textContent).toBe('Service ticket abuse');
    expect(title.className).toContain('text-[21px]');
  });
});
