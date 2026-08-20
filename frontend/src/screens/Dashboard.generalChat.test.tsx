// The Dashboard's Ask box handed every question to the Hunt Console with the
// objective prefilled — "just a cheap copy-paste of the hunt page" (owner,
// 2026-08-06). The slot now holds the general chat: it ANSWERS, and proposes a
// hunt only when the question needs a sweep.
//
// Two Dashboard-level properties are pinned here, both about the slot rather
// than the chat itself (GeneralChatPanel.test.tsx covers the panel): asking no
// longer navigates anywhere, and a deployment with the kill switch off renders
// no box at all — rather than one whose first GET is a guaranteed 403.
import { act, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AboutInfo } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue([]),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations: vi.fn().mockResolvedValue({ rows: [], total: 0, running: 0, truePositives: 0, totalAll: 0, active: false, limit: 100, offset: 0 }),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
  getDetectionTuningSummary: vi.fn().mockResolvedValue(null),
  getAbout: vi.fn(),
  getGeneralChat: vi.fn(),
  postGeneralChat: vi.fn(),
  // Setup-health card: unconditional on mount, so every Dashboard-rendering
  // test needs it named or the global fetch guard rejects loudly. Green here
  // (this file isn't about setup health), so the admin-only detail read is
  // never reached regardless of role.
  getMe: vi.fn().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' }),
  getPreflight: vi.fn().mockResolvedValue({ status: 'green', failing: 0, warned: 0, checked_at: '2026-08-19T00:00:00+00:00' }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-08-19T00:00:00+00:00' }),
}));

import { Dashboard } from './Dashboard';
import { getAbout, getGeneralChat, postGeneralChat } from '../lib/api';

const about = (generalChatEnabled: boolean): AboutInfo & { general_chat_enabled: boolean } => ({
  version: '1.2.6',
  repo_url: 'https://example.invalid/soc-ai',
  license: 'AGPL-3.0',
  update_check_enabled: false,
  general_chat_enabled: generalChatEnabled,
});

function Here() {
  const loc = useLocation();
  return <div data-testid="here">{loc.pathname}</div>;
}

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <Dashboard />
      <Here />
    </MemoryRouter>,
  );

/** Let every mount fetch settle (the About probe gates the chat slot). */
const settle = () => new Promise((r) => setTimeout(r, 0));

beforeEach(() => {
  sessionStorage.clear();
  // mockClear only (implementations survive): calls accumulate across tests,
  // and "was the doomed GET issued?" is an assertion about THIS test's calls.
  vi.clearAllMocks();
  vi.mocked(getAbout).mockResolvedValue(about(true));
  vi.mocked(getGeneralChat).mockResolvedValue({ messages: [], pending: false });
  vi.mocked(postGeneralChat).mockResolvedValue({ messages: [], pending: false });
});

describe('Dashboard "Ask soc-ai" slot', () => {
  it('answers in place instead of handing the question to the Hunt Console', async () => {
    mount();
    const box = await screen.findByPlaceholderText(/ask/i);
    vi.mocked(postGeneralChat).mockResolvedValue({
      messages: [
        { role: 'user', text: 'what datasets do I have?' },
        { role: 'assistant', text: 'Zeek conn, Suricata alerts, and Windows events.' },
      ],
      pending: false,
    });

    fireEvent.change(box, { target: { value: 'what datasets do I have?' } });
    // `act` around the click flushes the send's already-resolved promise and the
    // state update it schedules, so the assertion below is deterministic rather
    // than a race against a wall clock. This test previously used a bare click +
    // findByText and failed ONLY on the loaded CI runner (green in isolation,
    // green in local full runs, ~5 pipelines lost to it). Neither raising the
    // wait nor serialising test files fixed it, because the runner also runs the
    // 16-minute backend job alongside this one: no timeout is large enough when
    // the box is that starved. Removing the wait removes the dependency.
    await act(async () => {
      fireEvent.click(screen.getByLabelText('Send'));
    });

    // act() flushes the send's promise chain, which covers the common case — but
    // useChatThread also fires a mount re-sync (fetchThread) that can still be in
    // flight here, and on a starved box those two interleave in orders one act
    // drain cannot settle. Reproduced at 16 CPU spinners on 8 cores: ~1 run in 3
    // failed, and always FAST (~325ms) — getByText asking before the reply landed,
    // not a genuine absence. findByText retries, covering both the flushed and the
    // still-arriving case, and testTimeout (15s) now sits above asyncUtilTimeout
    // (5s) so a REAL miss still reports "unable to find" instead of a bare
    // killed-mid-wait timeout.
    expect(await screen.findByText('Zeek conn, Suricata alerts, and Windows events.')).toBeTruthy();
    expect(vi.mocked(postGeneralChat).mock.calls[0][0]).toBe('what datasets do I have?');
    // The whole point of the replacement: the analyst never left the Dashboard.
    expect(screen.getByTestId('here').textContent).toBe('/dashboard');
  });

  it('sits below the numbers it used to outrank', async () => {
    // Dogfood B2b (2026-08-11): the composer held the largest above-the-fold
    // band on the landing screen, pushing the KPI tiles and the outcomes chart
    // under it — the assistant outranking the answer the analyst opened the app
    // for. Hierarchy, not demotion: the box is still on the screen and still
    // works (the test above), it just no longer leads.
    mount();
    const composer = await screen.findByPlaceholderText(/ask about your environment/i);
    const kpi = screen.getByText('Awaiting investigation');
    const outcomes = screen.getByText('Investigation outcomes');
    const recent = screen.getByText('Recent investigations');

    const leads = (a: Element, b: Element) =>
      Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
    expect(leads(kpi, composer)).toBe(true);
    expect(leads(outcomes, composer)).toBe(true);
    // Both number surfaces, not just the chart. Below `lg` the grid collapses
    // to one column and DOM order IS reading order, so this is the whole
    // narrow-width hierarchy: KPIs → the numbers → the assistant. A first pass
    // at the demotion gave the rail `order-first` to keep the chat high, which
    // hoisted the entire rail — chat, Auto-Investigate, quality, posture — over
    // the outcomes chart and pushed it below the fold at 900px (dogfood,
    // 2026-08-12). CSS order is invisible to this assertion, so it is pinned
    // directly: no `order-*` utility may lift the rail past the numbers.
    expect(leads(recent, composer)).toBe(true);
    const rail = composer.closest('.flex-col.gap-4')!;
    // The `:` in the character class matches ANY variant prefix (lg:, md:,
    // max-lg:, …), not just `lg:`. The NARROW variants are the ones that bite:
    // `max-lg:order-first` — the natural way to "lift the chat below lg without
    // touching lg+" — reproduces the 900px defect exactly, and a `(lg:)?`-only
    // regex waved it through (proven by experiment during review). This
    // assertion is the sole guard on the fix, since the DOM-order checks above
    // pass either way (CSS order never moves the DOM), so it must cover the
    // whole family.
    expect(rail.className).not.toMatch(/(^|[\s:])order-/);
  });

  it('renders no chat box, and no doomed GET, when the kill switch is off', async () => {
    vi.mocked(getAbout).mockResolvedValue(about(false));
    mount();
    await screen.findByText('Investigation outcomes');
    await settle();

    expect(screen.queryByPlaceholderText(/ask/i)).toBeNull();
    // GET /api/v1/chat 403s when general_chat_enabled is off — an operator who
    // switched the assistant off must not get an error bubble on their landing
    // screen. The kill switch is why /about carries the flag at all.
    expect(getGeneralChat).not.toHaveBeenCalled();
  });
});
