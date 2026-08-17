// What the investigation surfaces may claim when the grid stops answering.
//
// Degraded-grid UI dogfood, 2026-08-14 (D6/D8). Clicking "Re-run investigation"
// against a down grid changed not one pixel: the post-click screenshot was
// byte-identical to the pre-click one, status chip still reading "complete ·
// 1m 14s" and verdict card still reading "TRUE POSITIVE · 0.92 CONFIDENCE" over
// a re-run that never began. Both start handlers ended in an empty catch, and
// the 503 they threw away carried the sentence written for the analyst. The
// analyst is left choosing between two wrong beliefs — the re-run is underway,
// or the button is dead — with nothing on screen to tell them apart.
//
// So these assert on RENDERED TEXT, never on a handler having been called: the
// handler already ran, and already did nothing visible. A handler-called
// assertion passes against the broken code.
//
// The controls carry equal weight. A re-run that WORKS must hand off silently,
// and an ordinary completed run must grow no warning — a screen that turns into
// an error wall when it could still answer is this batch's own failure mode.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv, InvestigationList, InvestigationRow } from '../lib/types';

const startHunt = vi.hoisted(() => vi.fn());
const requestMoreInfo = vi.hoisted(() => vi.fn());
const listInvestigations = vi.hoisted(() => vi.fn());
const listSavedViews = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  startHunt,
  requestMoreInfo,
  listInvestigations,
  listSavedViews,
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst', role: 'analyst', status: '' }),
}));

import { ApiError } from '../lib/api';
import { Investigation } from './Investigation';
import { Investigations } from './Investigations';

// The 503 the hunt route actually returns, verbatim off the wire: `detail.hint`
// is the sentence meant for the analyst, and api.ts puts it on ApiError.message.
const GRID_HINT =
  'The Security Onion grid (Elasticsearch) is slow or unreachable — retry shortly';
const gridDown = () => new ApiError(GRID_HINT, 503, 'grid_unavailable');

// api.ts's two transport failures — no response at all, so no status. The
// second is a QUESTION, which is why the punctuation guard below is not /\.\./.
const TIMED_OUT =
  'Request timed out — the soc-ai API (or Security Onion behind it) is slow or down.';
const NO_ROUTE = 'Network error — is the soc-ai API reachable?';

/** Prose with parentheses and dashes in it — match it literally. */
const literal = (s: string) => new RegExp(s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));

/** Our sentence joined onto somebody else's, ending it twice. */
const DOUBLED_STOP = /[.!?…]\s*[.!?]/;

const baseInv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-emotet-1',
    name: 'ET MALWARE Win32/Emotet CnC Activity (POST)',
    kind: 'suricata',
    host: '192.0.2.41',
    ip: '198.51.100.147',
    verdict: 'true_positive',
    conf: 0.92,
    rationale: 'Beaconing cadence, not user traffic.',
    summary: [{ t: 'text', v: 'periodic sessions' }],
    status: 'complete',
    elapsedLabel: '1m 14s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

const mountInv = (over: Partial<Inv> = {}, onReHunt?: (id: string) => void) =>
  render(
    <MemoryRouter>
      <Investigation inv={baseInv(over)} layout="page" onReHunt={onReHunt} />
    </MemoryRouter>,
  );

/** The needs-more-info shape that renders the "Request more info" button. */
const nmi = (): Partial<Inv> => ({
  verdict: 'needs_more_info',
  conf: 0.4,
  fallback: null,
  openQuestions: ['Did the host resolve the domain before connecting?'],
});

const clickReRun = () =>
  fireEvent.click(screen.getByRole('button', { name: /Re-run investigation/ }));
const clickRequestInfo = () =>
  fireEvent.click(screen.getByRole('button', { name: /Request more info/ }));

/** Whatever the screen ended up saying about the click, as text. */
const reportText = async (): Promise<string> =>
  (await screen.findByRole('alert')).textContent ?? '';

beforeEach(() => {
  startHunt.mockReset();
  requestMoreInfo.mockReset();
  listInvestigations.mockReset();
  listSavedViews.mockReset();
  listSavedViews.mockResolvedValue([]);
});

describe('a re-run the grid refused (D6)', () => {
  it("puts the server's own hint on the screen", async () => {
    startHunt.mockRejectedValue(gridDown());
    mountInv();
    clickReRun();

    const text = await reportText();
    expect(text).toMatch(literal(GRID_HINT));
    // A refusal is a fact about the SERVER, and this one answered — say so.
    expect(text).toMatch(/refused/i);
    expect(text).not.toMatch(DOUBLED_STOP);
  });

  it('survives the poll that follows it — the click leaves a durable record', async () => {
    startHunt.mockRejectedValue(gridDown());
    const { rerender } = mountInv();
    clickReRun();
    await reportText();

    // The container polls the same investigation every 2.5s and hands back a
    // fresh object with the same id. A notice that a re-render clears is a toast
    // with extra steps, and this action has no other trace.
    rerender(
      <MemoryRouter>
        <Investigation inv={baseInv({ elapsedSec: 75 })} layout="page" />
      </MemoryRouter>,
    );
    expect((await reportText())).toMatch(literal(GRID_HINT));
  });

  it('is dismissible, and a second attempt starts from a clean screen', async () => {
    startHunt.mockRejectedValue(gridDown());
    mountInv();
    clickReRun();
    await reportText();

    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());

    // And the next click clears it before it can be confused for the new one.
    startHunt.mockResolvedValue('INV-2');
    clickReRun();
    await waitFor(() => expect(startHunt).toHaveBeenCalledTimes(2));
    expect(screen.queryByRole('alert')).toBeNull();
  });
});

describe('a re-run that got no answer at all (D6)', () => {
  it('does not claim the run failed to start', async () => {
    startHunt.mockRejectedValue(new Error(TIMED_OUT));
    mountInv();
    clickReRun();

    const text = await reportText();
    // The client's 20s budget aborted the request; the backend may have accepted
    // the run and be working on it. "Failed" is a claim only an answer supports.
    expect(text).toMatch(/no answer/i);
    expect(text).not.toMatch(/refused/i);
    expect(text).not.toMatch(/failed to start/i);
    // Unknown is not failure — and the analyst is told where to find out.
    expect(text).toMatch(/may have started anyway/i);
    expect(text).toMatch(/Investigations list/i);
    expect(text).toMatch(literal(TIMED_OUT));
  });

  it("keeps the punctuation of a transport message that is a question", async () => {
    startHunt.mockRejectedValue(new Error(NO_ROUTE));
    mountInv();
    clickReRun();

    const text = await reportText();
    expect(text).toMatch(literal(NO_ROUTE));
    expect(text).not.toMatch(DOUBLED_STOP);
  });
});

describe('a "Request more info" the grid refused (D6)', () => {
  it("puts the server's own hint on the screen", async () => {
    requestMoreInfo.mockRejectedValue(gridDown());
    mountInv(nmi());
    clickRequestInfo();

    const text = await reportText();
    expect(text).toMatch(literal(GRID_HINT));
    expect(text).toMatch(/refused/i);
  });

  it('reports no answer as no answer', async () => {
    requestMoreInfo.mockRejectedValue(new Error(TIMED_OUT));
    mountInv(nmi());
    clickRequestInfo();

    const text = await reportText();
    expect(text).toMatch(/no answer/i);
    expect(text).not.toMatch(/refused/i);
    expect(text).toMatch(literal(TIMED_OUT));
  });
});

describe('the healthy path is left alone (D6 control)', () => {
  it('mounts a completed investigation with nothing to warn about', () => {
    mountInv();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByText('Beaconing cadence, not user traffic.')).toBeTruthy();
  });

  it('hands a successful re-run to the container and says nothing', async () => {
    startHunt.mockResolvedValue('INV-2');
    const onReHunt = vi.fn();
    mountInv({}, onReHunt);
    clickReRun();

    await waitFor(() => expect(onReHunt).toHaveBeenCalledWith('INV-2'));
    expect(screen.queryByRole('alert')).toBeNull();
    // Not merely "no alert role": no error prose anywhere on the screen.
    expect(screen.queryByText(/refused/i)).toBeNull();
    expect(screen.queryByText(/no answer/i)).toBeNull();
  });

  it('hands a successful "Request more info" over the same way', async () => {
    requestMoreInfo.mockResolvedValue('INV-3');
    const onReHunt = vi.fn();
    mountInv(nmi(), onReHunt);
    clickRequestInfo();

    await waitFor(() => expect(onReHunt).toHaveBeenCalledWith('INV-3'));
    expect(screen.queryByRole('alert')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// D8 — the list row that outlived a failed re-run
// ---------------------------------------------------------------------------

/** A list row, with the per-alert latest-run fields the endpoint carries. */
const row = (
  over: Partial<InvestigationRow> & {
    latestRunId?: string;
    latestRunStatus?: string;
    latestRunWhen?: string;
  },
): InvestigationRow =>
  ({
    id: 'INV-1',
    name: 'ET MALWARE Win32/Emotet CnC Activity (POST)',
    kind: 'suricata',
    verdict: 'true_positive',
    conf: 0.92,
    host: '192.0.2.41',
    dst: '198.51.100.147',
    status: 'complete',
    when: '10m',
    ts: '2026-08-14T01:00:00+00:00',
    alertId: 'ev-emotet-1',
    isPrimary: true,
    fallback: false,
    latestRunId: 'INV-1',
    latestRunStatus: 'complete',
    latestRunWhen: '10m',
    ...over,
  }) as InvestigationRow;

const listOf = (rows: InvestigationRow[]): InvestigationList => ({
  rows,
  total: rows.length,
  running: 0,
  truePositives: rows.filter((r) => r.verdict === 'true_positive').length,
  totalAll: rows.length,
  active: false,
  limit: 50,
  offset: 0,
});

const mountList = () =>
  render(
    <MemoryRouter initialEntries={['/investigations']}>
      <Investigations />
    </MemoryRouter>,
  );

describe('a failed re-run under a stale verdict (D8)', () => {
  it('says so on the representative row, without an expand', async () => {
    // Three re-investigations against a down grid; this alert's newest run died
    // and the older complete one is still primary. The list showed a bare "1
    // earlier" chip, so a batch that mostly died read as a mostly-calm list.
    listInvestigations.mockResolvedValue(
      listOf([
        row({ latestRunId: 'INV-9', latestRunStatus: 'error', latestRunWhen: 'now' }),
        row({
          id: 'INV-9',
          verdict: 'untriaged',
          conf: null,
          status: 'error',
          when: 'now',
          isPrimary: false,
          latestRunId: 'INV-9',
          latestRunStatus: 'error',
          latestRunWhen: 'now',
        }),
      ]),
    );
    const { container } = mountList();
    await screen.findAllByText('ET MALWARE Win32/Emotet CnC Activity (POST)');

    // The row an analyst reads at a glance carries the outcome, collapsed.
    expect(screen.getByText('newest run failed')).toBeTruthy();
    // And the verdict it is still showing is genuinely the older one — this is a
    // disclosure on the primary row, not a demotion of it.
    expect(container.textContent).toContain('True positive');
  });

  it('names the run it is pointing at, so the failure is one click away', async () => {
    listInvestigations.mockResolvedValue(
      listOf([row({ latestRunId: 'INV-9', latestRunStatus: 'error', latestRunWhen: 'now' })]),
    );
    mountList();
    await screen.findAllByText('ET MALWARE Win32/Emotet CnC Activity (POST)');
    expect(screen.getByText('newest run failed').closest('button')).toBeTruthy();
  });

  it('leaves an ordinary row alone when its newest run is itself (control)', async () => {
    // The over-correction: a completed investigation nobody re-ran must not grow
    // a warning, and neither must a row that IS its alert's newest failure — its
    // Status column already says Error, and saying it twice is noise.
    listInvestigations.mockResolvedValue(
      listOf([
        row({}),
        row({
          id: 'INV-8',
          alertId: 'ev-scan-1',
          name: 'ET SCAN Nmap Scripting Engine',
          verdict: 'untriaged',
          conf: null,
          status: 'error',
          latestRunId: 'INV-8',
          latestRunStatus: 'error',
        }),
      ]),
    );
    mountList();
    await screen.findByText('ET SCAN Nmap Scripting Engine');
    expect(screen.queryByText(/newest run/)).toBeNull();
  });

  it('claims nothing on a payload that predates the fields (control)', async () => {
    // An SPA outliving its backend gets rows with no latest-run fields at all.
    // That is not evidence that nothing failed, so the row says nothing rather
    // than inventing an all-clear or a warning.
    const legacy = row({});
    delete (legacy as { latestRunId?: string }).latestRunId;
    delete (legacy as { latestRunStatus?: string }).latestRunStatus;
    listInvestigations.mockResolvedValue(listOf([legacy]));
    mountList();
    await screen.findByText('ET MALWARE Win32/Emotet CnC Activity (POST)');
    expect(screen.queryByText(/newest run/)).toBeNull();
  });
});
