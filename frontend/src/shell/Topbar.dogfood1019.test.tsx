// Dogfood 2026-10-19: the bell, the health pill and the search box.
import { act, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getWorkspaces: vi.fn(),
  getNotifications: vi.fn(),
  getHealth: vi.fn(),
  getNeedsYouCount: vi.fn(),
}));

import { getHealth, getNeedsYouCount, getNotifications, getWorkspaces, type NeedsYouCount } from '../lib/api';
import { ShellProvider } from './ShellContext';
import { Topbar, notificationSummary } from './Topbar';

const needsYou = (total: number, extra: Partial<NeedsYouCount> = {}): NeedsYouCount => ({
  leads_needing_decision: total,
  unread_shadow_hits: 0,
  untriaged_groups: 0,
  needs_more_info: 0,
  pending_actions: 0,
  total,
  unknown: [],
  alert_window: '7d',
  verdict_window: '30d',
  alert_floor: false,
  ...extra,
});

const flush = () => act(async () => { await vi.advanceTimersByTimeAsync(0); });
const bell = () => screen.getByRole('button', { name: /^Notifications/ });
const mount = () =>
  render(
    <MemoryRouter>
      <ShellProvider>
        <Topbar />
      </ShellProvider>
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers();
  localStorage.clear();
  vi.mocked(getWorkspaces).mockResolvedValue([]);
  vi.mocked(getNotifications).mockResolvedValue([]);
  vi.mocked(getNeedsYouCount).mockResolvedValue(needsYou(0));
  vi.mocked(getHealth).mockResolvedValue({
    es: { ok: true, detail: 'ok' },
    llm: { ok: true, detail: 'ok' },
    so: { ok: true, detail: 'ok' },
    pcap: null,
  });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

// R1-D18. The badge read "34+" and the accessible name read "34 need you".
describe('bell name states a floor', () => {
  it('says "or more" when a part of the count is unknown', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue(
      needsYou(34, { untriaged_groups: null, unknown: ['untriaged_groups'] }),
    );
    const { container } = mount();
    await flush();
    expect(container.querySelector('[data-testid="notif-badge"]')?.textContent).toBe('34+');
    expect(bell()).toHaveAccessibleName('Notifications, 34 or more need you');
  });

  it('keeps the plain count when every part was read', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue(needsYou(34));
    mount();
    await flush();
    expect(bell()).toHaveAccessibleName('Notifications, 34 need you');
  });
});

// H1-D10. The bell header said "Nothing needs you · 3 notifications" while the
// Dashboard tile said "0+" and "Could not count the alert groups."
describe('bell header with an unknown part', () => {
  it('does not say nothing needs you when a part could not be counted', () => {
    expect(notificationSummary(0, 3, true)).toBe('Could not count what needs you · 3 notifications');
    expect(notificationSummary(0, 0, true)).toBe('Could not count what needs you');
  });

  it('states it in the open panel', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue(
      needsYou(0, { untriaged_groups: null, unknown: ['untriaged_groups'] }),
    );
    vi.mocked(getNotifications).mockResolvedValue([
      { id: 'hunt-done:1', tone: 'accent', title: 'Hunt finished: no threat found. Sweep', when: '1h', href: null },
    ]);
    mount();
    await flush();
    expect(bell()).toHaveAccessibleName('Notifications, could not count what needs you');
    act(() => bell().click());
    expect(screen.getByTestId('notif-summary').textContent).toBe('Could not count what needs you · 1 notification');
  });
});

// H1-D8. The pill said "3 degraded" in amber when all three dependencies were
// down, and the popover said "down" for each.
describe('health pill separates down from degraded', () => {
  it('says down in red when the dependencies do not answer', async () => {
    vi.mocked(getHealth).mockResolvedValue({
      es: { ok: false, detail: 'Connection refused', kind: 'refused' },
      llm: { ok: false, detail: 'Connection refused', kind: 'refused' },
      so: { ok: false, detail: 'Connection refused' },
      pcap: null,
    });
    mount();
    await flush();
    const pill = screen.getByTitle('Upstream health');
    expect(pill.textContent).toBe('3 down');
    expect(pill.getAttribute('data-state')).toBe('down');
  });

  it('says degraded in amber for a slow or overloaded dependency', async () => {
    vi.mocked(getHealth).mockResolvedValue({
      es: { ok: false, detail: 'answered the probe in 4.3 s', kind: 'slow' },
      llm: { ok: true, detail: 'ok' },
      so: { ok: false, detail: 'HTTP 429', kind: 'overloaded' },
      pcap: null,
    });
    mount();
    await flush();
    const pill = screen.getByTitle('Upstream health');
    expect(pill.textContent).toBe('2 degraded');
    expect(pill.getAttribute('data-state')).toBe('degraded');
  });

  it('names both when one is down and one is slow', async () => {
    vi.mocked(getHealth).mockResolvedValue({
      es: { ok: false, detail: 'answered late', kind: 'slow' },
      llm: { ok: false, detail: 'did not answer the probe in 5 s', kind: 'timeout' },
      so: { ok: true, detail: 'ok' },
      pcap: null,
    });
    mount();
    await flush();
    const pill = screen.getByTitle('Upstream health');
    expect(pill.textContent).toBe('1 down, 1 degraded');
    act(() => pill.click());
    const panel = screen.getByRole('dialog', { name: 'Upstream health' });
    expect(panel.textContent).toContain('Grid: Elasticsearch degraded');
    expect(panel.textContent).toContain('Model gateway down');
  });
});

// H1-D24. The search box showed the Mac key on Linux.
describe('palette shortcut label', () => {
  it('shows Ctrl K off macOS', async () => {
    vi.stubGlobal('navigator', { ...navigator, platform: 'Linux x86_64', userAgent: 'Mozilla/5.0 (X11; Linux x86_64)' });
    mount();
    await flush();
    const trigger = screen.getByRole('button', { name: /Search or jump to/ });
    expect(trigger.textContent).toContain('Ctrl K');
    expect(trigger.textContent).not.toContain('⌘');
  });

  it('shows the command key on macOS', async () => {
    vi.stubGlobal('navigator', { ...navigator, platform: 'MacIntel', userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)' });
    mount();
    await flush();
    expect(screen.getByRole('button', { name: /Search or jump to/ }).textContent).toContain('⌘K');
  });
});
