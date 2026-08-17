// What the Alerts screen may claim when the grid stops answering.
//
// Degraded-grid UI dogfood, 2026-08-14 (D2/D7/D16). Driven through four sick
// grids, this screen printed "0 untriaged · 0 detections · 0 events in window"
// above its own "Couldn't load this view" card, and a chip row of confident
// zeros beside it. Every one of those numbers was unknown: the query 503'd and
// the counts were derived from the empty array left behind. A false all-clear
// on the top line an analyst scans first outranks any loud error, so these
// tests pin the three count sites SEPARATELY — they are independent, and fixing
// one of them is the shape a partial fix takes.
//
// The control matters as much as the outage: a healthy grid with genuinely zero
// alerts is an ordinary, good answer, and it must still say zero.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../lib/api';
import type { AlertGroup } from '../lib/types';
import { ToastProvider } from '../lib/toast';
import { ShellProvider } from '../shell/ShellContext';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn(),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
  listSavedViews: vi.fn().mockResolvedValue([]),
  getInvestigation: vi.fn(() => new Promise(() => {})),
  startAutoTriage: vi.fn(),
  getAutoTriageStatus: vi.fn(() => new Promise(() => {})),
}));

import { Alerts } from './Alerts';
import { getAlerts, startAutoTriage } from '../lib/api';

// The 503 the grid routes actually return, verbatim off the wire: `detail.hint`
// is the sentence meant for the analyst, and api.ts puts it on ApiError.message.
const GRID_HINT =
  'The Security Onion grid (Elasticsearch) is slow or unreachable — retry shortly';
const gridDown = () => new ApiError(GRID_HINT, 503, 'grid_unavailable');

/** The hint is prose with parentheses in it — match it literally, not as a group. */
const literal = (s: string) => new RegExp(s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));

/**
 * Our sentence joined onto somebody else's, ending it twice. Every terminal
 * mark, not just a doubled period: the messages we quote are written elsewhere
 * (the wire's `detail.hint`, api.ts's transport errors) and one of them is a
 * question. A `/\.\./` guard cannot see "reachable?." at all.
 */
const DOUBLED_STOP = /[.!?…]\s*[.!?]/;

const mount = () =>
  render(
    <ToastProvider>
      <MemoryRouter initialEntries={['/alerts']}>
        <ShellProvider>
          <Alerts />
        </ShellProvider>
      </MemoryRouter>
    </ToastProvider>,
  );

/** The header's count line and the footer's, by their own prose. */
const headerLine = () => screen.getByText(/untriaged ·/).textContent ?? '';
const footerLine = () =>
  screen.getByText(/grouped · click a row to expand events/).textContent ?? '';

/**
 * The view chips, read off the toolbar. They are the only text-bearing
 * `aria-pressed` buttons on the screen (the density pair is icon-only), and a
 * chip's text is its label with its badge appended — "All6", or just "All" when
 * it carries no badge.
 */
const chipTexts = (): string[] =>
  screen
    .getAllByRole('button')
    .filter((b) => b.hasAttribute('aria-pressed') && (b.textContent ?? '').trim() !== '')
    .map((b) => (b.textContent ?? '').trim());

beforeEach(() => {
  vi.mocked(getAlerts).mockReset();
  vi.mocked(startAutoTriage).mockReset();
});

describe('Alerts on a grid that refused the query (D2)', () => {
  beforeEach(() => {
    vi.mocked(getAlerts).mockRejectedValue(gridDown());
  });

  it('does not report zero untriaged for a count it never obtained', async () => {
    mount();
    await screen.findByText("Couldn't load this view");

    expect(headerLine()).not.toContain('0 untriaged');
    expect(headerLine()).toContain('— untriaged');
  });

  it('renders no badge on any view chip rather than a zero badge', async () => {
    mount();
    await screen.findByText("Couldn't load this view");

    // The chips are still there — degrade the claim, not the screen.
    expect(chipTexts()).toEqual(['Mine', 'In review', 'Critical', 'Needs decision', 'All']);
    for (const text of chipTexts()) expect(text).not.toMatch(/\d/);
  });

  it('does not report zero detections in the footer', async () => {
    mount();
    await screen.findByText("Couldn't load this view");

    expect(footerLine()).not.toContain('0 detections');
    expect(footerLine()).toContain('— detections');
  });
});

// D16 — the card's remedy is "retry shortly", so it needs something to click.
describe('the failed-view card (D16)', () => {
  it('offers a Retry that re-runs the query the card is about', async () => {
    vi.mocked(getAlerts).mockRejectedValue(gridDown());
    mount();
    await screen.findByText("Couldn't load this view");
    expect(vi.mocked(getAlerts)).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByText('Retry'));

    await waitFor(() => expect(vi.mocked(getAlerts)).toHaveBeenCalledTimes(2));
  });
});

// D7 — the same click, reported two different ways, because they are two
// different facts. A server that answered and refused can be quoted; a request
// that got no answer cannot be called a failure at all.
describe('a Bulk Investigate that never started (D7)', () => {
  beforeEach(() => {
    vi.mocked(getAlerts).mockRejectedValue(gridDown());
  });

  const clickBulkInvestigate = async () => {
    mount();
    await screen.findByText("Couldn't load this view");
    fireEvent.click(screen.getByText('Bulk Investigate'));
  };

  /**
   * The toast, and only the toast. Scoped deliberately: the list's own error
   * card already carries the grid's hint in its Details disclosure, so a
   * document-wide search for that sentence passes without this fix ever
   * running — which is exactly the false green this file exists to avoid.
   */
  const toaster = () => within(screen.getByRole('region', { name: 'Notifications' }));

  it('quotes the refusal the server sent instead of dropping it', async () => {
    vi.mocked(startAutoTriage).mockRejectedValue(gridDown());
    await clickBulkInvestigate();

    // The 503's own hint carries both the cause and the next step; the old
    // toast said "Bulk Investigate failed to start" and threw the hint away.
    const notice = await waitFor(() => toaster().getByText(literal(GRID_HINT)));
    expect(notice.textContent).not.toContain('failed to start');
    // The server's sentence arrives punctuated; joining ours to it must not
    // leave "…retry shortly.." on screen.
    expect(notice.textContent).not.toMatch(DOUBLED_STOP);
  });

  it('does not claim a request that got no answer failed to start', async () => {
    // What a stalled grid actually produces: api.ts's 20s client budget aborts
    // the POST, so there is no response and no status — while the backend goes
    // on running the sweep it already accepted. The screen cannot know it did
    // not start, so it must not say so.
    vi.mocked(startAutoTriage).mockRejectedValue(
      new Error('Request timed out — the soc-ai API (or Security Onion behind it) is slow or down.'),
    );
    await clickBulkInvestigate();

    const notice = await waitFor(() => toaster().getByText(/No answer to Bulk Investigate/));
    expect(notice.textContent).not.toContain('failed to start');
    // …and it names the surface that does know, so the analyst checks there
    // rather than clicking again and running the same sweep twice.
    expect(notice.textContent).toContain('Auto-Investigate tile');
    expect(notice.textContent).not.toMatch(DOUBLED_STOP);
  });

  it('keeps the transport’s own punctuation when that sentence is a question', async () => {
    // The other half of the transport branch, verbatim off api.ts: a fetch that
    // fails for any reason other than the client budget throws THIS, and it
    // ends in a question mark. Appending our full stop to it printed
    // "…is the soc-ai API reachable?." on screen.
    vi.mocked(startAutoTriage).mockRejectedValue(
      new Error('Network error — is the soc-ai API reachable?'),
    );
    await clickBulkInvestigate();

    const notice = await waitFor(() => toaster().getByText(/No answer to Bulk Investigate/));
    expect(notice.textContent).toContain('Network error — is the soc-ai API reachable?');
    expect(notice.textContent).not.toMatch(DOUBLED_STOP);
    expect(notice.textContent?.trimEnd().endsWith('reachable?')).toBe(true);
  });

  it('still closes the sentence when the refusal it quotes is our own fallback', async () => {
    // The other side of the punctuation rule: a refusal that carried no hint
    // falls back to a sentence we wrote, and ours arrive unpunctuated.
    vi.mocked(startAutoTriage).mockRejectedValue(new ApiError('', 503, 'grid_unavailable'));
    await clickBulkInvestigate();

    const notice = await waitFor(() => toaster().getByText(/Bulk Investigate was refused/));
    expect(notice.textContent).toContain('The API answered 503.');
    expect(notice.textContent).not.toMatch(DOUBLED_STOP);
  });

  it('leaves the failure on screen after the click, not just a toast that expires', async () => {
    vi.mocked(startAutoTriage).mockRejectedValue(gridDown());
    await clickBulkInvestigate();

    // A durable record beside the control that was clicked: the toast used to
    // be an 'info' one, gone at 6s, leaving no trace the click had happened.
    const strip = await waitFor(() =>
      screen
        .getAllByRole('alert')
        .find((el) => (el.textContent ?? '').includes('Bulk Investigate was refused')),
    );
    expect(strip).toBeTruthy();
    expect(strip?.textContent).toContain(GRID_HINT);
    // The strip is the durable copy of the toast's sentence — it inherits the
    // same joining, so it inherits the same guard.
    expect(strip?.textContent).not.toMatch(DOUBLED_STOP);
  });
});

describe('Alerts whose refresh failed on top of rows it already has (D2 control)', () => {
  // Degrade the claim, not the screen. A foreground refetch that fails keeps
  // the rows it already loaded (useAsync.ts:100), and the counts describe THOSE
  // rows — so they are known, and an em-dash here would be its own lie. This is
  // why the count helpers key off the data and not off `error`.
  it('keeps counting the rows still on screen while showing the failure', async () => {
    const group: AlertGroup = {
      id: 'g1',
      name: 'ET SCAN Test Detection',
      kind: 'suricata',
      sev: 'high',
      count: 3,
      verdict: 'true_positive',
      conf: 0.9,
      latest: '2m ago',
      inherited: false,
      events: [],
    };
    vi.mocked(getAlerts).mockResolvedValueOnce([group]).mockRejectedValue(gridDown());
    mount();
    await screen.findByText('ET SCAN Test Detection');

    // A dependency change re-runs the query in the foreground; this one 503s.
    fireEvent.click(screen.getByText('Hide acknowledged'));
    await screen.findByText("Couldn't load this view");

    expect(screen.getByText('ET SCAN Test Detection')).toBeTruthy();
    expect(headerLine()).toContain('1 detection');
    expect(headerLine()).toContain('3 events');
    expect(headerLine()).not.toContain('—');
    expect(footerLine()).toContain('1 detection');
  });
});

describe('Alerts on a healthy grid with nothing in the window (D2 control)', () => {
  beforeEach(() => {
    vi.mocked(getAlerts).mockResolvedValue([]);
  });

  it('still says zero, because a quiet shift is a real answer', async () => {
    mount();
    await screen.findByText('No detections match this view.');

    expect(headerLine()).toBe('0 untriaged · 0 detections · 0 events in window');
    expect(footerLine()).toBe('0 detections · grouped · click a row to expand events');
    expect(chipTexts()).toEqual(['Mine0', 'In review0', 'Critical0', 'Needs decision0', 'All0']);
    expect(screen.queryByText("Couldn't load this view")).toBeNull();
  });
});
