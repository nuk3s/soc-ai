// The Topbar mounts on every in-shell route and drives two of the app's
// hottest pollers: /notifications every 15s (four DB queries a call) and
// /health every 60s. Both used to be bare setIntervals — an analyst parking a
// handful of tabs over a weekend kept every one of them hitting the API around
// the clock. These pin the fix: no poll while the tab is hidden, and one
// immediate refresh on return to visible so the bell is current the moment the
// analyst looks again (the house guard, lib/useAsync.ts:118).
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { useEffect } from 'react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getWorkspaces: vi.fn(),
  getNotifications: vi.fn(),
  getHealth: vi.fn(),
}));

// The Topbar calls useNavigate() to follow a notification — stub it so a test
// can assert the target. MemoryRouter below stays real.
const navigateMock = vi.fn();
vi.mock('react-router-dom', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-router-dom')>()),
  useNavigate: () => navigateMock,
}));

import { emitNeedsYouChanged, getHealth, getNotifications, getWorkspaces } from '../lib/api';
import { ShellProvider, useShell } from './ShellContext';
import { Topbar, notificationSummary } from './Topbar';

const NOTIF_MS = 15_000;

// happy-dom derives document.hidden from visibilityState; shadow it with a
// mutable getter so a test can park and un-park the tab.
let hidden = false;

/** Advance the clock (firing the pollers) AND settle the promise chains. */
const tick = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
/** Settle already-resolved promises without moving the clock. */
const flush = () => tick(0);
/** The bell. Its name carries the count, so match the prefix. */
const bell = () => screen.getByRole('button', { name: /^Notifications/ });

/** Toggle tab visibility and dispatch the event the effects listen for. */
const setHidden = (v: boolean) => {
  hidden = v;
  act(() => {
    document.dispatchEvent(new Event('visibilitychange'));
  });
};

const mount = () =>
  render(
    <MemoryRouter>
      <ShellProvider>
        <Topbar />
      </ShellProvider>
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.clearAllMocks(); // call history is per-test — don't carry counts across
  vi.useFakeTimers();
  hidden = false;
  Object.defineProperty(document, 'hidden', { configurable: true, get: () => hidden });
  vi.mocked(getWorkspaces).mockResolvedValue([]);
  vi.mocked(getNotifications).mockResolvedValue([]);
  vi.mocked(getHealth).mockResolvedValue({
    es: { ok: true, detail: 'ok' },
    llm: { ok: true, detail: 'ok' },
    so: { ok: true, detail: 'ok' },
    pcap: null,
  });
});

afterEach(() => {
  vi.useRealTimers();
});

describe('Topbar pollers respect tab visibility', () => {
  it('stops polling notifications and health while the tab is hidden', async () => {
    mount();
    await flush();
    // One immediate load of each on mount.
    expect(getNotifications).toHaveBeenCalledTimes(1);
    expect(getHealth).toHaveBeenCalledTimes(1);

    setHidden(true); // going hidden must not itself fetch
    await flush();
    expect(getNotifications).toHaveBeenCalledTimes(1);
    expect(getHealth).toHaveBeenCalledTimes(1);

    // 20 notification intervals (and several health intervals) pass with the
    // tab backgrounded — not one poll fires.
    await tick(NOTIF_MS * 20);
    expect(getNotifications).toHaveBeenCalledTimes(1);
    expect(getHealth).toHaveBeenCalledTimes(1);
  });

  it('refreshes once on return to visible and resumes the live poll', async () => {
    mount();
    await flush();
    setHidden(true);
    await tick(NOTIF_MS * 3);
    expect(getNotifications).toHaveBeenCalledTimes(1);

    // Coming back to the tab re-reads both surfaces immediately, without
    // waiting out an interval.
    setHidden(false);
    await flush();
    expect(getNotifications).toHaveBeenCalledTimes(2);
    expect(getHealth).toHaveBeenCalledTimes(2);

    // …and the 15s notifications poll is live again.
    await tick(NOTIF_MS);
    expect(getNotifications).toHaveBeenCalledTimes(3);
  });
});

// The pill is the product's one always-on trust indicator, and it used to cover
// Elasticsearch and the model gateway only. Every acknowledge, escalate and case
// write travels the Security Onion API, so with that API hung the pill said
// "connected" on the same screen as a setup-health card reporting a Security
// Onion timeout (dogfood 2026-09-07, D1).
describe('Topbar health pill covers every upstream it claims', () => {
  it('does not say connected while the Security Onion API is down', async () => {
    vi.mocked(getHealth).mockResolvedValue({
      es: { ok: true, detail: 'ok' },
      llm: { ok: true, detail: 'ok' },
      so: { ok: false, detail: 'the API took the request but did not answer in time' },
      pcap: null,
    });
    const { getByTitle } = mount();
    await flush();
    const pill = getByTitle('Upstream health');
    expect(pill.textContent).not.toContain('connected');
    expect(pill.textContent).toContain('1 degraded');
  });

  it('lists Security Onion as its own row in the dropdown', async () => {
    vi.mocked(getHealth).mockResolvedValue({
      es: { ok: true, detail: 'ok' },
      llm: { ok: true, detail: 'ok' },
      so: { ok: false, detail: 'so.example.com — /api/info answered HTTP 403' },
      pcap: null,
    });
    const { getByTitle, getByText } = mount();
    await flush();
    act(() => {
      getByTitle('Upstream health').click();
    });
    expect(getByText('Security Onion API')).toBeTruthy();
    expect(getByText(/answered HTTP 403/)).toBeTruthy();
  });

  it('still says connected when every upstream is healthy', async () => {
    const { getByTitle } = mount();
    await flush();
    expect(getByTitle('Upstream health').textContent).toContain('connected');
  });
});

describe('Topbar badge counts actionable notifications only', () => {
  it('does not badge when every notification is informational (accent)', async () => {
    vi.mocked(getNotifications).mockResolvedValue([
      { id: 'inv-done:1', tone: 'accent', title: 'Verdict false_positive: ET INFO X', when: '2m', href: '/investigation/1' },
      { id: 'inv-done:2', tone: 'accent', title: 'Verdict false_positive: ET INFO Y', when: '5m', href: '/investigation/2' },
    ]);
    const { container } = mount();
    await flush();
    expect(container.querySelector('[data-testid="notif-badge"]')).toBeNull();
  });

  it('badges only the danger/warn count when informational items are mixed in', async () => {
    vi.mocked(getNotifications).mockResolvedValue([
      { id: 'inv-done:1', tone: 'accent', title: 'Verdict false_positive: ET INFO X', when: '2m', href: null },
      { id: 'inv-done:2', tone: 'danger', title: 'Verdict true_positive: ET MALWARE Z', when: '3m', href: null },
      { id: 'hunt-done:3', tone: 'warn', title: 'Hunt finished — 2 findings: sweep', when: '4m', href: null },
    ]);
    const { container } = mount();
    await flush();
    expect(container.querySelector('[data-testid="notif-badge"]')?.textContent).toBe('2');
  });
});

// The bell holds a notice per unread shadow hit. An analyst who read a hit on
// the Hunts page watched the strip and the sidebar move and the bell stand
// still for up to 15 s, so one number read two ways on one screen. The bell
// reads the list again the moment a hit is read or a lead changes.
describe('Topbar bell follows a hit that was read', () => {
  it('reads the notifications again when what needs the analyst changes', async () => {
    mount();
    await flush();
    expect(getNotifications).toHaveBeenCalledTimes(1);

    act(() => {
      emitNeedsYouChanged();
    });
    await flush();
    expect(getNotifications).toHaveBeenCalledTimes(2);
  });
});

// The bell is the app's primary alerting affordance, and each row in its
// dropdown was a div with an onClick: Tab landed on every row's Dismiss and on
// "View all", never on the row, so the one thing a keyboard user could do to a
// true-positive notice from the bell was make it disappear.
describe('Topbar notification rows are reachable from the keyboard', () => {
  const truePositive = {
    id: 'inv:1',
    tone: 'danger' as const,
    title: 'Verdict true_positive: ET MALWARE Z',
    when: 'now',
    href: '/investigation/INV-1',
  };

  it('renders a row with somewhere to go as a button that navigates there', async () => {
    vi.mocked(getNotifications).mockResolvedValue([truePositive]);
    mount();
    await flush();
    act(() => {
      bell().click();
    });

    // A button is in the Tab order and fires on Enter and Space; a div with an
    // onClick is neither, so the role query alone is the keyboard contract.
    const row = screen.getByRole('button', { name: /true positive: ET MALWARE Z/i });
    act(() => {
      row.focus();
    });
    expect(document.activeElement).toBe(row);
    fireEvent.click(row);
    expect(navigateMock).toHaveBeenCalledWith('/investigation/INV-1');
  });

  it('keeps Dismiss a separate target and leaves a row with nowhere to go inert', async () => {
    vi.mocked(getNotifications).mockResolvedValue([
      truePositive,
      { id: 'dep:es', tone: 'warn', title: 'Elasticsearch unreachable', when: '3m', href: null },
    ]);
    mount();
    await flush();
    act(() => {
      bell().click();
    });

    expect(screen.queryByRole('button', { name: /Elasticsearch unreachable/ })).toBeNull();
    expect(screen.getByText('Elasticsearch unreachable')).toBeTruthy();

    fireEvent.click(screen.getAllByLabelText('Dismiss')[0]);
    expect(navigateMock).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: /true positive: ET MALWARE Z/i })).toBeNull();
  });

  it('opens once from a click on the row outside the text, and Dismiss does not open it', async () => {
    // The keyboard fix made the body a button. A mouse user who clicks the
    // tone dot or the row padding must still get the old whole-row
    // behaviour, and the body click bubbling to the row must not open it
    // twice.
    // A fresh id: the test above dismissed inv:1, and a dismissal lives in
    // local storage across tests.
    const rowNotice = { ...truePositive, id: 'inv:2', href: '/investigation/INV-2' };
    vi.mocked(getNotifications).mockResolvedValue([rowNotice]);
    mount();
    await flush();
    act(() => {
      bell().click();
    });

    const body = screen.getByRole('button', { name: /true positive: ET MALWARE Z/i });
    const row = body.parentElement!;
    fireEvent.click(row);
    expect(navigateMock).toHaveBeenCalledTimes(1);
    expect(navigateMock).toHaveBeenCalledWith('/investigation/INV-2');

    // Opening closed the dropdown. Open it again: Dismiss sits inside the
    // row, and its click must not bubble into a second navigation.
    act(() => {
      bell().click();
    });
    fireEvent.click(screen.getAllByLabelText('Dismiss')[0]);
    expect(navigateMock).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: /true positive: ET MALWARE Z/i })).toBeNull();
  });
});

// The bell and the health pill ignored Escape and a click on the page. Their
// click-catcher sat inside the blurred top bar, which clipped it to the bar, so
// only a click on the bar closed them. The open panel also covered "Clear all"
// and "Test LLM" (D5, D6, RC9, RD6, RD8).
describe('Topbar dropdowns close like the account menu', () => {
  const notices = [
    { id: 'inv:9', tone: 'danger' as const, title: 'Verdict true_positive: ET MALWARE Q', when: 'now', href: '/investigation/INV-9' },
    { id: 'inv:10', tone: 'warn' as const, title: 'Investigation needs more information', when: '2m', href: '/investigation/INV-10' },
    { id: 'inv:11', tone: 'accent' as const, title: 'Verdict false_positive: ET INFO R', when: '5m', href: '/investigation/INV-11' },
  ];

  beforeEach(() => {
    localStorage.clear();
    vi.mocked(getWorkspaces).mockResolvedValue([]);
    vi.mocked(getNotifications).mockResolvedValue(notices);
    vi.mocked(getHealth).mockResolvedValue({
      es: { ok: true, detail: 'ok' },
      llm: { ok: true, detail: 'ok' },
    } as never);
  });

  it('names the count on the bell and states its state', async () => {
    mount();
    await flush();
    const b = screen.getByRole('button', { name: 'Notifications, 2 need attention' });
    expect(b).toHaveAttribute('aria-haspopup', 'dialog');
    expect(b).toHaveAttribute('aria-expanded', 'false');
    act(() => b.click());
    expect(b).toHaveAttribute('aria-expanded', 'true');
    // The badge counts two rows and the panel shows three: the header says so.
    expect(screen.getByTestId('notif-summary').textContent).toBe('2 need attention · 1 more');
  });

  it('closes the bell on Escape and gives focus back to the bell', async () => {
    mount();
    await flush();
    act(() => bell().click());
    expect(screen.getByRole('dialog', { name: 'Notifications' })).toBeTruthy();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('dialog', { name: 'Notifications' })).toBeNull();
    expect(document.activeElement).toBe(bell());
  });

  it('closes the bell on a click on the page, and leaves no layer over the page', async () => {
    const { container } = render(<button type="button">Clear all</button>);
    mount();
    await flush();
    act(() => bell().click());
    // Nothing fixed and full-screen may cover the page under the panel.
    expect(document.querySelector('.fixed.inset-0')).toBeNull();
    const clearAll = within(container).getByRole('button', { name: 'Clear all' });
    fireEvent.mouseDown(clearAll);
    expect(screen.queryByRole('dialog', { name: 'Notifications' })).toBeNull();
  });

  it('keeps the bell open on a click inside its panel', async () => {
    mount();
    await flush();
    act(() => bell().click());
    fireEvent.mouseDown(screen.getByRole('dialog', { name: 'Notifications' }));
    expect(screen.getByRole('dialog', { name: 'Notifications' })).toBeTruthy();
  });

  it('closes the health popover on Escape and on a page click', async () => {
    mount();
    await flush();
    const pill = screen.getByRole('button', { name: /connected/ });
    expect(pill).toHaveAttribute('aria-haspopup', 'dialog');
    act(() => pill.click());
    expect(pill).toHaveAttribute('aria-expanded', 'true');
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('dialog', { name: 'Upstream health' })).toBeNull();
    act(() => pill.click());
    fireEvent.mouseDown(document.body);
    expect(screen.queryByRole('dialog', { name: 'Upstream health' })).toBeNull();
  });

  it('puts the bell panel before Help in the Tab order', async () => {
    mount();
    await flush();
    act(() => bell().click());
    const panel = screen.getByRole('dialog', { name: 'Notifications' });
    const help = screen.getByRole('button', { name: 'Help and shortcuts' });
    // DOCUMENT_POSITION_FOLLOWING: the argument comes after the reference.
    expect(bell().compareDocumentPosition(panel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(panel.compareDocumentPosition(help) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });
});

describe('notificationSummary', () => {
  it('relates the badge count to the row count', () => {
    expect(notificationSummary(12, 2)).toBe('2 need attention · 10 more');
    expect(notificationSummary(1, 1)).toBe('1 needs attention');
    expect(notificationSummary(4, 0)).toBe('None need attention · 4 more');
  });
});

// The avatar for a workspace named by its address showed the first digit, which
// read as a count (RD15).
describe('Workspace avatar', () => {
  it('shows a glyph for an address-named workspace', async () => {
    vi.mocked(getWorkspaces).mockResolvedValue([{ name: '192.0.2.46', env: 'prod' }] as never);
    vi.mocked(getNotifications).mockResolvedValue([]);
    vi.mocked(getHealth).mockResolvedValue({ es: { ok: true, detail: '' }, llm: { ok: true, detail: '' } } as never);
    mount();
    await flush();
    // The avatar box holds the glyph and no digit.
    expect(screen.getByTestId('ws-glyph-ip').parentElement!.textContent).toBe('');
  });

  it('keeps the first letter for a named workspace', async () => {
    vi.mocked(getWorkspaces).mockResolvedValue([{ name: 'soc-east', env: 'prod' }] as never);
    vi.mocked(getNotifications).mockResolvedValue([]);
    vi.mocked(getHealth).mockResolvedValue({ es: { ok: true, detail: '' }, llm: { ok: true, detail: '' } } as never);
    mount();
    await flush();
    expect(screen.queryByTestId('ws-glyph-ip')).toBeNull();
    expect(screen.getByTitle('Current workspace').textContent).toBe('Ssoc-east');
  });
});

// The machine page read "agent:<uuid>" in the top bar over a page titled with
// the machine name (range dogfood 2026-10-05, C5). The top bar shows the name
// the page reports, and the key rides in the tooltip only.
describe('Topbar breadcrumb on a machine page', () => {
  const KEY = 'agent:9c53d823-8137-47c0-b78e-38e2314e5dcd';

  function NameSetter({ name }: { name: { key: string; name: string } | null }) {
    const { setCrumbName } = useShell();
    useEffect(() => setCrumbName(name), [name, setCrumbName]);
    return null;
  }

  const mountAt = (path: string, name: { key: string; name: string } | null) =>
    render(
      <MemoryRouter initialEntries={[path]}>
        <ShellProvider>
          <Routes>
            <Route
              path="/hosts/:key"
              element={
                <>
                  <Topbar />
                  <NameSetter name={name} />
                </>
              }
            />
            <Route path="/investigation/:id" element={<Topbar />} />
          </Routes>
        </ShellProvider>
      </MemoryRouter>,
    );

  it('shows the machine name and keeps the key in the tooltip', async () => {
    mountAt(`/hosts/${encodeURIComponent(KEY)}`, { key: KEY, name: 'web-01' });
    await flush();
    const crumb = screen.getByTestId('topbar-crumb2');
    expect(crumb.textContent).toBe('web-01');
    expect(crumb.getAttribute('title')).toBe(KEY);
  });

  it('shows no raw key before the name arrives', async () => {
    mountAt(`/hosts/${encodeURIComponent(KEY)}`, null);
    await flush();
    const crumb = screen.getByTestId('topbar-crumb2');
    expect(crumb.textContent).toBe('machine');
    expect(crumb.textContent).not.toContain('agent:');
    expect(crumb.getAttribute('title')).toBe(KEY);
  });

  it('ignores a name reported for another key', async () => {
    mountAt(`/hosts/${encodeURIComponent(KEY)}`, { key: 'agent:other', name: 'db-02' });
    await flush();
    expect(screen.getByTestId('topbar-crumb2').textContent).toBe('machine');
  });

  it('keeps the id of a page that is not a machine page', async () => {
    mountAt('/investigation/01M44S6F4JPXDCK7FC19KVS0D9', null);
    await flush();
    const crumb = screen.getByTestId('topbar-crumb2');
    expect(crumb.textContent).toBe('01M44S6F4JPXDCK7FC19KVS0D9');
    expect(crumb.getAttribute('title')).toBeNull();
  });
});
