// When a tour starts by itself, where the state goes, and the "?" menu.
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getMe: vi.fn(),
  getMyTours: vi.fn(),
  putMyTours: vi.fn(),
}));

import { ApiError, getMe, getMyTours, putMyTours } from '../lib/api';
import { ToastProvider } from '../lib/toast';
import { SessionProvider } from '../shell/Session';
import { ShellProvider, useShell } from '../shell/ShellContext';
import { ALERTS_TOUR, HOSTS_TOUR, WELCOME_TOUR } from './content';
import { HelpMenu } from './HelpMenu';
import { OFF_KEY, STATE_KEY } from './state';
import { allowTourAutoStartInTests, resetTourAutoStartForTests } from './testing';
import { type TourTimings, TourProvider } from './TourProvider';
import type { Tour, ToursState } from './types';

const FAST: TourTimings = {
  auto: { pollMs: 5, settleMs: 0, maxMs: 60 },
  manual: { pollMs: 5, settleMs: 0, maxMs: 60 },
};

const SIGNED_IN = { username: 'admin', role: 'admin', status: '', signed_in: true };
const AUTH_OFF = { username: 'anonymous', role: 'admin', status: '', signed_in: false };

/** Every anchor of a tour, as plain elements. */
function Anchors({ tour, skip = [] }: { tour: Tour; skip?: string[] }) {
  return (
    <>
      {tour.steps
        .filter((s) => !skip.includes(s.anchor))
        .map((s) => (
          <div key={s.anchor} data-tour={s.anchor}>
            {s.anchor}
          </div>
        ))}
    </>
  );
}

function ShortcutsFlag() {
  const { shortcutsOpen } = useShell();
  return shortcutsOpen ? <div data-testid="shortcuts-open" /> : null;
}

function Go({ to }: { to: string }) {
  const navigate = useNavigate();
  return (
    <button type="button" onClick={() => navigate(to)}>
      go {to}
    </button>
  );
}

/** A shell with the welcome anchors and the real "?" menu, over two pages. */
function mount(path = '/alerts', opts: { welcomeSkip?: string[] } = {}) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ShellProvider>
        <ToastProvider>
          <SessionProvider>
            <TourProvider timings={FAST}>
              <div>
                {WELCOME_TOUR.steps
                  .filter((s) => s.scope !== 'page' && s.anchor !== 'help')
                  .filter((s) => !(opts.welcomeSkip ?? []).includes(s.anchor))
                  .map((s) => (
                    <div key={s.anchor} data-tour={s.anchor}>
                      {s.anchor}
                    </div>
                  ))}
                <HelpMenu />
                <Go to="/alerts" />
                <Go to="/hosts" />
                <Go to="/nowhere" />
                <ShortcutsFlag />
              </div>
              <Routes>
                <Route path="/alerts" element={<Anchors tour={ALERTS_TOUR} />} />
                <Route path="/hosts" element={<Anchors tour={HOSTS_TOUR} />} />
                <Route path="*" element={<div>no tour here</div>} />
              </Routes>
            </TourProvider>
          </SessionProvider>
        </ToastProvider>
      </ShellProvider>
    </MemoryRouter>,
  );
}

const settle = () => act(async () => { await new Promise((r) => setTimeout(r, 120)); });
const card = () => screen.queryByRole('dialog');
const cardTitle = () => card()?.getAttribute('aria-labelledby') && document.getElementById(card()!.getAttribute('aria-labelledby')!)?.textContent;
const lastPut = (): ToursState => {
  const calls = vi.mocked(putMyTours).mock.calls;
  return calls[calls.length - 1][0];
};

/** Press Next until the tour ends with Done. */
async function finish() {
  for (let i = 0; i < 10; i++) {
    const done = screen.queryByRole('button', { name: 'Done' });
    if (done) {
      fireEvent.click(done);
      break;
    }
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
  }
  await settle();
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  vi.mocked(getMe).mockResolvedValue(SIGNED_IN);
  vi.mocked(getMyTours).mockResolvedValue({ off: false, seen: {} });
  vi.mocked(putMyTours).mockImplementation(async (s) => s);
});

afterEach(() => {
  cleanup();
  resetTourAutoStartForTests();
  vi.clearAllMocks();
});

describe('auto-start', () => {
  beforeEach(() => allowTourAutoStartInTests());

  it('runs the welcome tour first, then the tour of the page, and marks each seen on the server', async () => {
    mount('/alerts');
    await settle();
    expect(screen.getAllByRole('dialog')).toHaveLength(1);
    expect(cardTitle()).toBe(WELCOME_TOUR.steps[0].title);
    await finish();
    expect(lastPut().seen).toEqual({ welcome: WELCOME_TOUR.version });
    // The page tour follows. Never two tours at once.
    expect(screen.getAllByRole('dialog')).toHaveLength(1);
    expect(cardTitle()).toBe(ALERTS_TOUR.steps[0].title);
    await finish();
    expect(lastPut().seen).toEqual({ welcome: WELCOME_TOUR.version, alerts: ALERTS_TOUR.version });
    expect(card()).toBeNull();
  });

  it('starts a page tour once', async () => {
    vi.mocked(getMyTours).mockResolvedValue({ off: false, seen: { welcome: WELCOME_TOUR.version } });
    mount('/alerts');
    await settle();
    expect(cardTitle()).toBe(ALERTS_TOUR.steps[0].title);
    act(() => {
      fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Escape' });
    });
    await settle();
    expect(lastPut().seen.alerts).toBe(ALERTS_TOUR.version);
    // Away and back: the tour does not start again.
    fireEvent.click(screen.getByRole('button', { name: 'go /hosts' }));
    await settle();
    expect(cardTitle()).toBe(HOSTS_TOUR.steps[0].title);
    act(() => {
      fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Escape' });
    });
    fireEvent.click(screen.getByRole('button', { name: 'go /alerts' }));
    await settle();
    expect(card()).toBeNull();
  });

  it('starts a tour again when its version is higher than the stored one', async () => {
    vi.mocked(getMyTours).mockResolvedValue({
      off: false,
      seen: { welcome: WELCOME_TOUR.version, alerts: ALERTS_TOUR.version - 1 },
    });
    mount('/alerts');
    await settle();
    expect(cardTitle()).toBe(ALERTS_TOUR.steps[0].title);
  });

  it('starts nothing when the stored version is current', async () => {
    vi.mocked(getMyTours).mockResolvedValue({
      off: false,
      seen: { welcome: WELCOME_TOUR.version, alerts: ALERTS_TOUR.version },
    });
    mount('/alerts');
    await settle();
    expect(card()).toBeNull();
  });

  it('holds the page tour after the operator closes the welcome tour, until the route changes', async () => {
    mount('/alerts');
    await settle();
    expect(cardTitle()).toBe(WELCOME_TOUR.steps[0].title);
    act(() => {
      fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Escape' });
    });
    await settle();
    expect(card()).toBeNull();
    expect(lastPut().seen).toEqual({ welcome: WELCOME_TOUR.version });
    fireEvent.click(screen.getByRole('button', { name: 'go /hosts' }));
    await settle();
    expect(cardTitle()).toBe(HOSTS_TOUR.steps[0].title);
  });

  it('starts nothing when the operator turned the tours off', async () => {
    vi.mocked(getMyTours).mockResolvedValue({ off: true, seen: {} });
    mount('/alerts');
    await settle();
    expect(card()).toBeNull();
  });

  it('turns the tours off from the last step, and the "?" menu turns them on', async () => {
    mount('/alerts');
    await settle();
    for (let i = 0; i < 10 && !screen.queryByRole('button', { name: 'Done' }); i++) {
      fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    }
    fireEvent.click(screen.getByRole('button', { name: 'Turn off tours' }));
    await settle();
    expect(lastPut()).toEqual({ off: true, seen: { welcome: WELCOME_TOUR.version } });
    // Off: the page tour does not follow.
    expect(card()).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Help' }));
    fireEvent.click(await screen.findByRole('menuitem', { name: 'Turn on tours' }));
    await settle();
    expect(lastPut().off).toBe(false);
  });

  it('starts nothing when no anchor of the tour is on the page, and marks nothing', async () => {
    vi.mocked(getMyTours).mockResolvedValue({ off: false, seen: { welcome: WELCOME_TOUR.version } });
    mount('/nowhere');
    await settle();
    expect(card()).toBeNull();
    expect(putMyTours).not.toHaveBeenCalled();
  });

  it('ends a page tour on a route change and marks nothing', async () => {
    vi.mocked(getMyTours).mockResolvedValue({ off: false, seen: { welcome: WELCOME_TOUR.version } });
    mount('/alerts');
    await settle();
    expect(cardTitle()).toBe(ALERTS_TOUR.steps[0].title);
    // The overlay blocks page clicks; a route change can still come from the
    // history, a key or a link outside the page. Navigate under the overlay.
    fireEvent.click(screen.getByRole('button', { name: 'go /nowhere' }));
    await settle();
    expect(card()).toBeNull();
    expect(putMyTours).not.toHaveBeenCalled();
  });

  it('keeps the welcome tour on a route change while its step is in the shell', async () => {
    mount('/alerts');
    await settle();
    expect(cardTitle()).toBe(WELCOME_TOUR.steps[0].title);
    fireEvent.click(screen.getByRole('button', { name: 'go /hosts' }));
    await settle();
    expect(cardTitle()).toBe(WELCOME_TOUR.steps[0].title);
  });

  it('keeps the state in the browser with authentication off', async () => {
    vi.mocked(getMe).mockResolvedValue(AUTH_OFF);
    mount('/alerts');
    await settle();
    expect(cardTitle()).toBe(WELCOME_TOUR.steps[0].title);
    act(() => {
      fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Escape' });
    });
    await settle();
    expect(getMyTours).not.toHaveBeenCalled();
    expect(putMyTours).not.toHaveBeenCalled();
    expect(JSON.parse(localStorage.getItem(STATE_KEY)!)).toEqual({ off: false, seen: { welcome: 1 } });
  });

  it('falls back to the browser when the server has no user for the request', async () => {
    vi.mocked(getMe).mockRejectedValue(new Error('down'));
    vi.mocked(getMyTours).mockRejectedValue(new ApiError('no session', 401, 'no_session'));
    mount('/alerts');
    await settle();
    expect(cardTitle()).toBe(WELCOME_TOUR.steps[0].title);
  });

  it('starts nothing when the state read fails for another reason', async () => {
    vi.mocked(getMyTours).mockRejectedValue(new ApiError('down', 503));
    mount('/alerts');
    await settle();
    expect(card()).toBeNull();
  });

  it.each([
    ['navigator.webdriver', () => Object.defineProperty(navigator, 'webdriver', { configurable: true, get: () => true })],
    ['the localStorage switch', () => localStorage.setItem(OFF_KEY, '1')],
  ])('starts nothing under %s, and the "?" menu still opens a tour', async (_name, block) => {
    block();
    mount('/alerts');
    await settle();
    expect(card()).toBeNull();
    // An automated browser that never opens the menu sends no request.
    expect(getMyTours).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Help' }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Tour this page' }));
    await settle();
    expect(cardTitle()).toBe(ALERTS_TOUR.steps[0].title);
  });

  it('starts nothing for ?tour=off, and the tab keeps the switch', async () => {
    window.history.pushState({}, '', '/app/alerts?tour=off');
    try {
      mount('/alerts');
      await settle();
      expect(card()).toBeNull();
    } finally {
      window.history.pushState({}, '', '/');
    }
    cleanup();
    // The URL lost the switch; the tab kept it.
    mount('/alerts');
    await settle();
    expect(card()).toBeNull();
  });
});

describe('under vitest without the helper', () => {
  it('starts nothing by itself and reads nothing', async () => {
    mount('/alerts');
    await settle();
    expect(card()).toBeNull();
    expect(getMyTours).not.toHaveBeenCalled();
  });
});

describe('the "?" menu', () => {
  it('is a menu button with arrow keys, Escape and focus return', async () => {
    mount('/alerts');
    await settle();
    const button = screen.getByRole('button', { name: 'Help' });
    expect(button).toHaveAttribute('aria-haspopup', 'menu');
    expect(button).toHaveAttribute('data-tour', 'help');
    fireEvent.click(button);
    const menu = screen.getByRole('menu', { name: 'Help' });
    expect(button).toHaveAttribute('aria-expanded', 'true');
    const items = within(menu).getAllByRole('menuitem');
    expect(items.map((i) => i.getAttribute('aria-labelledby') ? document.getElementById(i.getAttribute('aria-labelledby')!)?.textContent : i.textContent)).toEqual([
      'Tour this page',
      'Tour soc-ai from the start',
      'Keyboard shortcuts',
      'Open the guide',
    ]);
    await waitFor(() => expect(items[0]).toHaveFocus());
    fireEvent.keyDown(menu, { key: 'ArrowDown' });
    expect(items[1]).toHaveFocus();
    fireEvent.keyDown(menu, { key: 'ArrowUp' });
    fireEvent.keyDown(menu, { key: 'ArrowUp' });
    expect(items[3]).toHaveFocus();
    fireEvent.keyDown(menu, { key: 'Home' });
    expect(items[0]).toHaveFocus();
    fireEvent.keyDown(menu, { key: 'End' });
    expect(items[3]).toHaveFocus();
    fireEvent.keyDown(menu, { key: 'Escape' });
    expect(screen.queryByRole('menu')).toBeNull();
    expect(button).toHaveFocus();
    // ArrowDown on the button opens the menu too.
    fireEvent.keyDown(button, { key: 'ArrowDown' });
    expect(screen.getByRole('menu')).toBeInTheDocument();
  });

  it('opens the guide in a new tab and the shortcut sheet', async () => {
    mount('/alerts');
    fireEvent.click(screen.getByRole('button', { name: 'Help' }));
    const guide = screen.getByRole('menuitem', { name: 'Open the guide' });
    expect(guide.getAttribute('href')).toBe('/app/guide/');
    expect(guide.getAttribute('target')).toBe('_blank');
    fireEvent.click(screen.getByRole('menuitem', { name: 'Keyboard shortcuts' }));
    expect(screen.getByTestId('shortcuts-open')).toBeInTheDocument();
    expect(screen.queryByRole('menu')).toBeNull();
  });

  it('turns off Tour this page on a page with no tour', async () => {
    mount('/nowhere');
    fireEvent.click(screen.getByRole('button', { name: 'Help' }));
    const item = screen.getByRole('menuitem', { name: 'Tour this page' });
    expect(item).toHaveAttribute('aria-disabled', 'true');
    expect(item).toHaveAccessibleDescription('This page has no tour.');
    fireEvent.click(item);
    await settle();
    expect(card()).toBeNull();
  });

  it('opens the tour of the page and returns the focus to the button on close', async () => {
    mount('/hosts');
    const button = screen.getByRole('button', { name: 'Help' });
    button.focus();
    fireEvent.click(button);
    fireEvent.click(screen.getByRole('menuitem', { name: 'Tour this page' }));
    await settle();
    expect(cardTitle()).toBe(HOSTS_TOUR.steps[0].title);
    act(() => {
      fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Escape' });
    });
    await settle();
    expect(button).toHaveFocus();
    expect(lastPut().seen.hosts).toBe(HOSTS_TOUR.version);
  });

  it('tours soc-ai from the start: the welcome tour only, and the page tours keep their state', async () => {
    // The owner decided on 2026-10-22: "from the start" replays the welcome
    // tour. It does not reset the page tours and does not turn the tours on.
    vi.mocked(getMyTours).mockResolvedValue({
      off: true,
      seen: { welcome: WELCOME_TOUR.version, alerts: ALERTS_TOUR.version, hosts: HOSTS_TOUR.version },
    });
    mount('/alerts');
    fireEvent.click(screen.getByRole('button', { name: 'Help' }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Tour soc-ai from the start' }));
    await settle();
    expect(cardTitle()).toBe(WELCOME_TOUR.steps[0].title);
    for (const call of vi.mocked(putMyTours).mock.calls) {
      expect(call[0].off).toBe(true);
      expect(call[0].seen.alerts).toBe(ALERTS_TOUR.version);
      expect(call[0].seen.hosts).toBe(HOSTS_TOUR.version);
    }
    fireEvent.keyDown(document, { key: 'Escape' });
    await settle();
    const calls = vi.mocked(putMyTours).mock.calls;
    const last = calls.length ? calls[calls.length - 1][0] : undefined;
    expect(last?.off ?? true).toBe(true);
    expect(last?.seen.alerts ?? ALERTS_TOUR.version).toBe(ALERTS_TOUR.version);
    expect(last?.seen.hosts ?? HOSTS_TOUR.version).toBe(HOSTS_TOUR.version);
  });

  it('skips a welcome step whose anchor is missing', async () => {
    mount('/alerts', { welcomeSkip: ['nav'] });
    fireEvent.click(screen.getByRole('button', { name: 'Help' }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Tour soc-ai from the start' }));
    await settle();
    expect(cardTitle()).toBe(WELCOME_TOUR.steps[1].title);
  });
});
