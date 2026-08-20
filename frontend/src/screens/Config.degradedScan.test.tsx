// A discovery scan that could not read the grid must not look like a clean one.
//
// Degraded-grid sweep, 2026-08-13: GET /internal-identifiers returns the scan's
// whole summary, errors included, and this section rendered one thing from it —
// the timestamp. So a scan taken with Security Onion unreachable (eight
// ConnectionError strings, nothing learned, nothing retired) drew exactly the
// header a scan that read every event and found nothing new draws, above lists
// that were short of the truth.
//
// The badge keys on `errors` and on nothing else. Not on a count: a settled
// network yields a scan that finds no new suffixes, and that scan is correct.
// Not on `notes` either — those are what a HEALTHY run reports, and a badge
// that fires nightly is a badge the operator stops seeing.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { InternalIdentifiers } from '../lib/api';

vi.mock('./AgentToolsPanel', () => ({ AgentToolsPanel: () => null }));
vi.mock('./ApiKeysPanel', () => ({ ApiKeysPanel: () => null }));
vi.mock('./DataSourcesPanel', () => ({ DataSourcesPanel: () => null }));
vi.mock('./EgressPolicyPanel', () => ({ EgressPolicyPanel: () => null }));
vi.mock('./NotificationsPanel', () => ({ NotificationsPanel: () => null }));
vi.mock('./RedactionPreviewPanel', () => ({ RedactionPreviewPanel: () => null }));
vi.mock('./DetectionTuningPanel', () => ({ DetectionTuningPanel: () => null }));
vi.mock('./MaintenancePanel', () => ({ MaintenancePanel: () => null }));
vi.mock('./RunbooksPanel', () => ({ RunbooksPanel: () => null }));
vi.mock('./AboutPanel', () => ({ AboutPanel: () => null }));

// One settings group so the page has something to build a layout from. The
// identifiers section is a frontend-owned panel and is spliced in regardless.
const GROUPS = vi.hoisted(() => [
  {
    title: 'Discovery',
    parent: 'Privacy & Egress',
    items: [
      {
        key: 'discovery_enabled',
        label: 'Discovery',
        help: 'Learn internal identifiers from your data.',
        source: 'db',
        apply: 'hot-apply',
        type: 'toggle',
        value: true,
        // Not a real day1 key, and this group's own pane is never the
        // section under test here (these tests deep-link straight to the
        // internal-identifiers panel) — the value is inert either way.
        day1: false,
      },
    ],
  },
]);

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getConfig: vi.fn(() => Promise.resolve({ groups: GROUPS, tokens: [], users: [], dangerHost: '' })),
  listUsers: vi.fn().mockResolvedValue({ users: [] }),
  listDangerSettings: vi.fn().mockResolvedValue([]),
  getGatewayModels: vi.fn().mockResolvedValue({ ok: true, models: [] }),
  getInternalIdentifiers: vi.fn(),
}));

import { getInternalIdentifiers } from '../lib/api';
import { Config } from './Config';

const LAST_SCAN = '2026-08-13T02:15:00+00:00';

/** The identifiers payload with only the last-scan summary varying. Groups stay
 *  empty on purpose: the lists a degraded scan failed to fill ARE empty, which
 *  is exactly why the empty list cannot be the signal. */
const payload = (
  last_summary: Record<string, unknown> | null,
  running = false,
): InternalIdentifiers => ({
  groups: [],
  last_scan: { running, last_scan: LAST_SCAN, last_summary, note: null },
});

beforeEach(() => {
  localStorage.clear();
  vi.mocked(getInternalIdentifiers).mockReset();
});

const mount = async (last_summary: Record<string, unknown> | null, running = false) => {
  vi.mocked(getInternalIdentifiers).mockResolvedValue(payload(last_summary, running));
  render(
    <MemoryRouter initialEntries={[{ pathname: '/config', hash: '#internal-identifiers' }] as never}>
      <Config />
    </MemoryRouter>,
  );
  // A managed list only renders once the identifiers request has resolved, so
  // this is the signal that the section has the scan record in hand.
  await screen.findByText('Domain suffixes');
};

describe('Internal identifiers — a degraded scan vs a quiet one', () => {
  it('marks the scan degraded when it recorded errors', async () => {
    // What a scan against an unreachable grid actually stores: one error per
    // query it could not run, and nothing learned or retired.
    await mount({
      scanned_events: 0,
      suffixes_found: 0,
      hosts_found: 0,
      cidrs_suggested: 0,
      retired: 0,
      errors: [
        'suffix query: ConnectionError',
        'host query: ConnectionError',
        'cidr query: ConnectionError',
      ],
      started_at: LAST_SCAN,
      finished_at: LAST_SCAN,
    });
    const note = await screen.findByTestId('identifier-scan-degraded');
    expect(note.textContent).toMatch(/Scan degraded/);
    expect(note.textContent).toMatch(/3 errors/);
    // The operator must read "what is below is not the whole picture", not
    // "something was logged".
    expect(note.textContent).toMatch(/incomplete/i);
    // Folded, the body note is gone; the header must still say so.
    expect(screen.getByTestId('identifier-scan-degraded-tag')).toBeTruthy();
  });

  it('marks a total failure degraded, where the summary is only the catch-all', async () => {
    // routes_discovery.py stores this when the scan task died outright — no
    // counters at all, so the timestamp was literally the only thing on screen.
    await mount({ errors: ['scan failed; see server logs'] });
    const note = await screen.findByTestId('identifier-scan-degraded');
    expect(note.textContent).toMatch(/1 error\b/);
  });

  it('says nothing about degradation after a clean scan', async () => {
    await mount({ scanned_events: 12000, suffixes_found: 2, hosts_found: 40, errors: [] });
    expect(screen.queryByTestId('identifier-scan-degraded')).toBeNull();
    expect(screen.queryByTestId('identifier-scan-degraded-tag')).toBeNull();
    // The timestamp is still there — this is not a test that the header emptied.
    expect(screen.getByText(/last scan:/)).toBeTruthy();
  });

  it('says nothing about degradation when a clean scan found nothing new', async () => {
    // A settled network: every identifier is already known, so a correct scan
    // learns and retires zero. Keying off a count would paint this degraded.
    await mount({
      scanned_events: 12000,
      internal_hosts_seen: 40,
      suffixes_found: 0,
      hosts_found: 0,
      cidrs_suggested: 0,
      retired: 0,
      errors: [],
    });
    expect(screen.queryByTestId('identifier-scan-degraded')).toBeNull();
    expect(screen.queryByTestId('identifier-scan-degraded-tag')).toBeNull();
  });

  it('says nothing about degradation when a healthy scan left advisory notes', async () => {
    // Advisory lines ride in their own field precisely so a healthy run does
    // not report trouble. A badge here would fire on every nightly scan.
    await mount({
      scanned_events: 12000,
      suffixes_found: 3,
      errors: [],
      notes: ['aggregation truncated at the 500-bucket cap'],
    });
    expect(screen.queryByTestId('identifier-scan-degraded')).toBeNull();
    expect(screen.queryByTestId('identifier-scan-degraded-tag')).toBeNull();
  });

  it('names what failed rather than only counting it', async () => {
    // Not every error in this channel is the grid. This one is a local
    // misconfiguration: an operator told to wait for Security Onion waits
    // forever, while the answer sits in the payload the screen already holds.
    await mount({
      scanned_events: 0,
      errors: ['no internal CIDRs configured; cannot scope internal source'],
    });
    const note = await screen.findByTestId('identifier-scan-degraded');
    expect(note.textContent).toMatch(/no internal CIDRs configured/);
  });

  it('shows the first errors and counts the rest', async () => {
    await mount({
      errors: [
        'dns.query: ConnectionError',
        'host.name: ConnectionError',
        'source.ip: ConnectionError',
        'destination.ip: ConnectionError',
      ],
    });
    const note = await screen.findByTestId('identifier-scan-degraded');
    expect(note.textContent).toMatch(/dns\.query: ConnectionError/);
    expect(note.textContent).toMatch(/2 more/);
  });

  it('says nothing about degradation when the server sent no summary', async () => {
    // An older server, or a process that has not scanned since it started.
    await mount(null);
    expect(screen.queryByTestId('identifier-scan-degraded')).toBeNull();
    expect(screen.queryByTestId('identifier-scan-degraded-tag')).toBeNull();
  });
});

// Degraded-grid sweep, 2026-08-14 (D13). `scanning` was set by the click
// handler and nothing else, so it died with the navigation: come back to this
// section while the scan is still grinding server-side and the button reads
// "Scan now", idle, over lists the scan has not finished writing. That is
// indistinguishable from a scan that finished and learned nothing, and the
// analyst's next move is to press it again.
//
// The running flag is already on the wire — `last_scan` is the same status
// object GET /discovery/scan answers with — so the section can adopt a scan it
// did not start.
describe('Internal identifiers — a scan that is still running says so', () => {
  it('shows a scan in flight on arrival, with no click', async () => {
    await mount({ scanned_events: 0, errors: [] }, true);
    const button = await screen.findByRole('button', { name: /scanning/i });
    expect(button).toBeDisabled();
    expect(screen.queryByRole('button', { name: /^scan now$/i })).toBeNull();
  });

  it('holds back the last scan’s timestamp while a new one is in flight', async () => {
    // The stamp dates the lists below it, and those are being rewritten as the
    // operator reads them.
    await mount({ scanned_events: 12000, errors: [] }, true);
    await screen.findByRole('button', { name: /scanning/i });
    expect(screen.queryByText(/last scan:/)).toBeNull();
  });

  it('holds back the previous scan’s degraded verdict while a new one runs', async () => {
    // A retry after a blind scan: the verdict on screen is being overwritten,
    // and the Hosts sweep note hides itself under the same rule.
    await mount({ errors: ['suffix query: ConnectionError'] }, true);
    await screen.findByRole('button', { name: /scanning/i });
    expect(screen.queryByTestId('identifier-scan-degraded')).toBeNull();
    expect(screen.queryByTestId('identifier-scan-degraded-tag')).toBeNull();
  });

  it('offers the scan, undimmed, when none is running', async () => {
    // The control: an idle button is the right answer when the server is idle,
    // and a section stuck on "Scanning…" would be this fix inverted.
    await mount({ scanned_events: 12000, errors: [] }, false);
    const button = await screen.findByRole('button', { name: /^scan now$/i });
    expect(button).not.toBeDisabled();
    expect(screen.getByText(/last scan:/)).toBeTruthy();
  });
});
