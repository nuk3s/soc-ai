// What the Alerts screen's counts are counting.
//
// Range dogfood: a list showing ONE row was captioned "59 detections", and the
// preset chips carried the same 59. Every number on the screen was measured
// against the array the grid returned, before any of the analyst's own
// narrowing was applied, so the caption described a list nobody was looking at.
// A count under a list is a claim about that list.
//
// The chips are the same claim in miniature: a chip's badge answers "how many
// rows would I get if I clicked this", so it has to be measured against the
// facets already in force. Otherwise the All chip and the footer, sitting on
// the same screen, print different numbers for the same list.
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '../lib/toast';
import { ShellProvider } from '../shell/ShellContext';
import type { AlertGroup } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn(),
  getAlertsEmptyReason: vi.fn(),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
  listSavedViews: vi.fn().mockResolvedValue([]),
  getInvestigation: vi.fn(() => new Promise(() => {})),
  startAutoTriage: vi.fn(),
  getAutoTriageStatus: vi.fn(() => new Promise(() => {})),
}));

import { queueOf } from '../test/alertQueue';
import { Alerts } from './Alerts';
import { getAlerts, getAlertsEmptyReason } from '../lib/api';

/** The group the range's one critical detection stood for. */
const CRITICAL: AlertGroup = {
  id: 'g-critical',
  name: 'ET EXPLOIT Suspicious Deserialization Attempt',
  kind: 'suricata',
  sev: 'critical',
  count: 4,
  verdict: 'untriaged',
  conf: null,
  latest: '2m ago',
  inherited: false,
  events: [],
};

/** Fifty-eight ordinary rows behind it, as the window really held them. */
const REST: AlertGroup[] = Array.from({ length: 58 }, (_, i) => ({
  ...CRITICAL,
  id: `g-${i}`,
  name: `ET INFO Routine Detection ${i}`,
  sev: i % 2 === 0 ? 'high' : 'low',
  count: 2,
}));

const ALL = [CRITICAL, ...REST]; // 59 detections

const mount = (url: string) =>
  render(
    <ToastProvider>
      <MemoryRouter initialEntries={[url]}>
        <ShellProvider>
          <Alerts />
        </ShellProvider>
      </MemoryRouter>
    </ToastProvider>,
  );

const headerLine = () => screen.getByText(/untriaged ·/).textContent ?? '';
const footerLine = () =>
  screen.getByText(/grouped · click a row to expand events/).textContent ?? '';

/** A chip's text is its label with its badge appended: "All59", or "All". */
const chipTexts = (): string[] =>
  screen
    .getAllByRole('button')
    .filter((b) => b.hasAttribute('aria-pressed') && (b.textContent ?? '').trim() !== '')
    .map((b) => (b.textContent ?? '').trim());

beforeEach(() => {
  vi.mocked(getAlerts).mockReset().mockResolvedValue(queueOf(ALL));
  vi.mocked(getAlertsEmptyReason).mockReset().mockResolvedValue({ reason: 'not_empty', hint: '' });
});

describe('Alerts counts what is on the screen', () => {
  it('captions the footer with the rows the analyst can see', async () => {
    mount('/alerts?sev=critical');
    await screen.findByText(CRITICAL.name);

    expect(screen.queryByText(REST[0].name)).toBeNull();
    expect(footerLine()).toMatch(/^1 detection ·/);
  });

  it('says the same thing on the header line', async () => {
    mount('/alerts?sev=critical');
    await screen.findByText(CRITICAL.name);

    // Four events on the one row that survived the facet, not the 120 the
    // window held across all fifty-nine.
    expect(headerLine()).toBe('1 untriaged · 1 detection · 4 events in window');
  });

  it('counts the preset chips after the facets are applied', async () => {
    mount('/alerts?sev=critical');
    await screen.findByText(CRITICAL.name);

    const chips = chipTexts();
    expect(chips).toContain('All1');
    expect(chips).toContain('Critical1');
    expect(chips).not.toContain('All59');
  });

  it('agrees with itself: the All chip and the footer describe one list', async () => {
    mount('/alerts?verdict=true_positive');
    // Nothing survives the facet, so wait on the chips carrying a badge at all
    // (they carry none until the fetch lands) rather than on a row.
    await waitFor(() => expect(chipTexts().some((t) => /All\d/.test(t))).toBe(true));

    expect(screen.queryByText(CRITICAL.name)).toBeNull();
    expect(footerLine()).toMatch(/^0 detections ·/);
    expect(chipTexts()).toContain('All0');
  });

  it('still counts every row when no facet narrows the list', async () => {
    // Negative control. A screen that answered "1 detection" whatever it was
    // showing would pass every test above and be a worse lie than the one being
    // fixed. Unnarrowed, the caption is the whole window.
    mount('/alerts');
    await screen.findByText(CRITICAL.name);

    expect(footerLine()).toMatch(/^59 detections ·/);
    expect(headerLine()).toBe('59 untriaged · 59 detections · 120 events in window');
    expect(chipTexts()).toContain('All59');
    expect(chipTexts()).toContain('Critical1');
  });
});

// ---------------------------------------------------------------------------
// The other way every number on that line can be wrong, and the harder one to
// see. The grid caps each terms aggregation at a fixed number of distinct
// groups and returns the biggest ones plus a lump sum for the rest. So the
// caption was a true count of what came back and a false count of what is
// there — and unlike a failed read it looks completely ordinary, because a
// number without a mark on it reads as a total.

describe('Alerts says when the queue is bigger than the rows', () => {
  it('renders the counts as floors and says why', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf(ALL, { truncated: true, other_docs: 41908 }));
    mount('/alerts');
    await screen.findByText(CRITICAL.name);

    // The "+" carries the claim; the clause carries the meaning. Neither on
    // its own is enough: a bare "+" is a mark somebody has to already know how
    // to read, and a sentence with plain numbers above it leaves two readings
    // on screen at once.
    expect(headerLine()).toContain('59+ detections');
    expect(headerLine()).toContain('120+ events in window');
    expect(headerLine()).toContain('more than the queue can show');
    const line = screen.getByText(/untriaged ·/);
    expect(line.getAttribute('title') ?? '').toMatch(/These numbers are floors/i);
  });

  it('leaves an uncapped queue alone', async () => {
    // NEGATIVE CONTROL. Every ordinary window is smaller than the ceiling, and
    // a caption that always hedged would be a caption nobody reads.
    vi.mocked(getAlerts).mockResolvedValue(queueOf(ALL));
    mount('/alerts');
    await screen.findByText(CRITICAL.name);

    expect(headerLine()).toBe('59 untriaged · 59 detections · 120 events in window');
    expect(screen.getByText(/untriaged ·/).getAttribute('title')).toBeNull();
  });

  it('does not infer the cap from a full-looking page', async () => {
    // The rule the host dossier's peer list learned the hard way: a page that
    // happens to be exactly cap-sized is not a cut one, and re-deriving the
    // flag from a copied constant goes quietly false the day the cap moves —
    // or, here, the day a muted rule is dropped after the cap is applied. Only
    // the server that cut can say it was cut.
    vi.mocked(getAlerts).mockResolvedValue(queueOf(ALL, { truncated: false, other_docs: 0 }));
    mount('/alerts');
    await screen.findByText(CRITICAL.name);

    expect(headerLine()).not.toContain('+');
    expect(screen.queryByText(/more than the queue can show/)).toBeNull();
  });
});
