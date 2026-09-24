// The audit-chain verify control — the Diagnostics panel's third probe,
// alongside Test ES / Test LLM. This is what makes the Operate hub's
// "Audit chain" card promise real (soc_ai/api/webui/routes_config.py:
// GET /config/audit/verify-chain).
//
// The endpoint is explicitly NOT fail-soft (its own docstring: it raises on
// an unreachable or partially-read index rather than answering), a
// capped-but-ok scan is its own honesty boundary (verify.py's module
// docstring: "a capped scan cannot claim the whole chain was verified... the
// caller MUST surface it"), and — since the epoch partition landed — so is a
// scan that crosses a process-restart boundary: the chain is verified PER
// EPOCH (cut at every genesis `seq=0` record, which never links back to
// whatever epoch preceded it — see soc_ai/audit/verify.py's module docstring
// for the chain-head recovery bug, fixed 2026-08-17, that made a 134-epoch
// chain a real prod shape), so "every epoch intact" is short of "one
// unbroken chain" and must not wear the same green livery. So there are FIVE
// outcomes, not two, each with its own line: intact (green ✓), partial
// (amber ⚠ — capped+ok, no checkmark), intact within N epochs (amber ⚠ — no
// checkmark, distinct from partial: nothing was capped, every epoch just
// checked out on its own), tampered (red ✗, now naming which epoch broke),
// and "could not verify" (amber ⚠ — a request failure, distinct from a
// partial-but-ran verification). A false all-clear outranks any 500, and a
// false tamper alarm is nearly as costly, so none of the five may ever be
// rendered as another — `expectOnlyOutcome` below pins that pairwise on every
// test, not just positively.
//
// Render setup mirrors Config.battery.test.tsx (the closest existing
// template for a focused sub-panel of Config.tsx): sibling panels stubbed to
// null (they don't mount — Config's master-detail content pane renders ONLY
// the selected section — but stubbing keeps this file inert to their own
// data needs), a minimal api mock, `<Config />` deep-linked straight to the
// Diagnostics section via the hash so the selected pane is the one under
// test without simulating nav clicks.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ErrorBoundary } from '../components/ErrorBoundary';

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

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  // No settings groups needed — PANELS entries (incl. `diagnostics`) are
  // spliced into the layout unconditionally, independent of `groups`.
  getConfig: vi.fn().mockResolvedValue({ groups: [], tokens: [], users: [], dangerHost: '' }),
  listUsers: vi.fn().mockResolvedValue({ users: [] }),
  listDangerSettings: vi.fn().mockResolvedValue([]),
  getGatewayModels: vi.fn().mockResolvedValue({ ok: true, models: [] }),
  getInternalIdentifiers: vi.fn().mockResolvedValue({
    groups: [],
    last_scan: { running: false, last_scan: null, last_summary: null, note: null },
  }),
  // The mount-time debounced fitness probe fires regardless of which section
  // is selected — must resolve to a real shape so its effect never throws.
  getModelFitness: vi.fn().mockResolvedValue({ grade: 'pass', model: 'x', legs: [], detail: 'ok' }),
  getModelBattery: vi.fn(),
  verifyAuditChain: vi.fn(),
}));

import { Config } from './Config';
import { verifyAuditChain } from '../lib/api';
import type { AuditChainVerifyResult } from '../lib/types';

function renderDiagnostics() {
  return render(
    <ErrorBoundary>
      <MemoryRouter initialEntries={['/config#diagnostics']}>
        <Config />
      </MemoryRouter>
    </ErrorBoundary>,
  );
}

const INTACT: AuditChainVerifyResult = {
  ok: true,
  records_verified: 42,
  first_broken_seq: null,
  first_seq: 1,
  last_seq: 42,
  capped: false,
  epochs: 1,
  first_broken_epoch_start: null,
  epochs_broken: 0,
  newest_broken_epoch_start: null,
  latest_epoch_broken: false,
  first_break_kind: null,
  first_break_detail: null,
  newest_break_kind: null,
  newest_break_detail: null,
  checked_at: '2026-08-19T10:00:00+00:00',
};

// Capped+ok: the scan hit soc_ai/audit/verify.py's max_records cap before
// exhausting the index. It genuinely covers only a PREFIX of the chain (the
// oldest records — the paging sort is timestamp ASCENDING), so `ok: true`
// here must not read as a full clean bill of health.
const CAPPED_INTACT: AuditChainVerifyResult = {
  ok: true,
  records_verified: 500_000,
  first_broken_seq: null,
  first_seq: 1,
  last_seq: 500_000,
  capped: true,
  epochs: 1,
  first_broken_epoch_start: null,
  epochs_broken: 0,
  newest_broken_epoch_start: null,
  latest_epoch_broken: false,
  first_break_kind: null,
  first_break_detail: null,
  newest_break_kind: null,
  newest_break_detail: null,
  checked_at: '2026-08-19T10:00:00+00:00',
};

// ok:true but epochs>1: every restart's own trail checked out (nothing
// capped, no tamper found in any of them), but the chain is verified PER
// EPOCH — cut at every process-restart boundary, since a genesis record's
// prev_hash never links back to whatever epoch preceded it (soc_ai/audit/
// verify.py's module docstring: the chain-head recovery bug, fixed
// 2026-08-17, that made a 134-epoch chain a real prod shape). So this is
// short of "one unbroken chain" and must not read as the same clean bill of
// health as INTACT, even though nothing here is capped or tampered.
const EPOCHED: AuditChainVerifyResult = {
  ok: true,
  records_verified: 9,
  first_broken_seq: null,
  first_seq: 0,
  last_seq: 4,
  capped: false,
  epochs: 3,
  first_broken_epoch_start: null,
  epochs_broken: 0,
  newest_broken_epoch_start: null,
  latest_epoch_broken: false,
  first_break_kind: null,
  first_break_detail: null,
  newest_break_kind: null,
  newest_break_detail: null,
  checked_at: '2026-08-19T10:00:00+00:00',
};

// Capped AND epochs>1 together: the scan hit soc_ai/audit/verify.py's
// max_records cap partway through a chain that was ALSO already fragmented
// into more than one restart (verify.py: "a capped scan verifies the OLDEST
// records — now the oldest EPOCHS"). Capped still wins the color/checkmark
// precedence — this renders as the same amber "Partial verification" line,
// not a sixth state — but the copy composes the epoch count in rather than
// silently dropping it: an un-composed "intact from the start of the chain"
// would overstate what a fragmented prefix actually proves.
const CAPPED_AND_EPOCHED: AuditChainVerifyResult = {
  ok: true,
  records_verified: 8,
  first_broken_seq: null,
  first_seq: 0,
  last_seq: 2,
  capped: true,
  epochs: 2,
  first_broken_epoch_start: null,
  epochs_broken: 0,
  newest_broken_epoch_start: null,
  latest_epoch_broken: false,
  first_break_kind: null,
  first_break_detail: null,
  newest_break_kind: null,
  newest_break_detail: null,
  checked_at: '2026-08-19T10:00:00+00:00',
};

// One break, and every epoch since verified intact (latest_epoch_broken:
// false) — the "old scar, clean now" shape, and the one prod's actual June
// finding takes once every epoch is checked rather than stopping at the
// first break.
const TAMPERED: AuditChainVerifyResult = {
  ok: false,
  records_verified: 42,
  first_broken_seq: 17,
  first_seq: 1,
  last_seq: 42,
  capped: false,
  epochs: 2,
  first_broken_epoch_start: '2026-08-01T00:00:00+00:00',
  epochs_broken: 1,
  newest_broken_epoch_start: '2026-08-01T00:00:00+00:00',
  latest_epoch_broken: false,
  // A real break carries WHAT it was. Two writers claiming one position
  // leaves records that each still match their own hash; an edit does not,
  // and the panel used to read identically for both.
  first_break_kind: 'duplicate_seq',
  first_break_detail: '2 records claim sequence 17, and each one still matches its own hash',
  newest_break_kind: 'duplicate_seq',
  newest_break_detail: '2 records claim sequence 17, and each one still matches its own hash',
  checked_at: '2026-08-19T10:00:00+00:00',
};

// Two independent breaks — the oldest and newest are named separately, and
// an intact epoch after the newest one earns the reassurance sentence.
const TWO_EPOCHS_BROKEN: AuditChainVerifyResult = {
  ok: false,
  records_verified: 20,
  first_broken_seq: 1,
  first_seq: 0,
  last_seq: 3,
  capped: false,
  epochs: 5,
  first_broken_epoch_start: '2026-06-26T21:55:52+00:00',
  epochs_broken: 2,
  newest_broken_epoch_start: '2026-06-27T02:13:00+00:00',
  latest_epoch_broken: false,
  first_break_kind: null,
  first_break_detail: null,
  newest_break_kind: null,
  newest_break_detail: null,
  checked_at: '2026-08-19T10:00:00+00:00',
};

// The MOST RECENT epoch itself is the broken one — nothing intact comes
// after it, so the loud variant fires instead of the reassuring one.
const LATEST_EPOCH_BROKEN: AuditChainVerifyResult = {
  ok: false,
  records_verified: 10,
  first_broken_seq: 1,
  first_seq: 0,
  last_seq: 3,
  capped: false,
  epochs: 3,
  first_broken_epoch_start: '2026-08-19T00:00:00+00:00',
  epochs_broken: 1,
  newest_broken_epoch_start: '2026-08-19T00:00:00+00:00',
  latest_epoch_broken: true,
  first_break_kind: null,
  first_break_detail: null,
  newest_break_kind: null,
  newest_break_detail: null,
  checked_at: '2026-08-19T10:00:00+00:00',
};

// Capped AND broken: the cap truncates the NEWEST end of the chain (fetch is
// oldest-first), so this scan cannot vouch for anything beyond its own
// prefix — neither "everything after X is intact" nor "the latest epoch is
// broken" is a claim it can honestly make, whichever way the scanned
// prefix's own tail happens to land.
const CAPPED_AND_TAMPERED: AuditChainVerifyResult = {
  ok: false,
  records_verified: 8,
  first_broken_seq: 1,
  first_seq: 0,
  last_seq: 2,
  capped: true,
  epochs: 2,
  first_broken_epoch_start: '2026-06-26T21:55:52+00:00',
  epochs_broken: 1,
  newest_broken_epoch_start: '2026-06-26T21:55:52+00:00',
  latest_epoch_broken: false,
  first_break_kind: null,
  first_break_detail: null,
  newest_break_kind: null,
  newest_break_detail: null,
  checked_at: '2026-08-19T10:00:00+00:00',
};

type Outcome = 'intact' | 'partial' | 'epoched' | 'tampered' | 'error';

const LINE_PATTERN: Record<Outcome, RegExp> = {
  // Tightened from a bare /chain intact/i: the epoched line below also opens
  // with "Chain intact" (honestly — the chain IS intact, just not provably
  // as ONE chain), so the pattern that must uniquely pick out the full-success
  // line needs the full stop that only follows it. LOAD-BEARING: the composed
  // capped+epoched line ("...records intact within N epochs from the start
  // of the chain...") never has the word "chain" immediately before "intact",
  // so it stays clear of this pattern too — don't loosen either half without
  // re-checking that composed line.
  intact: /chain intact\./i,
  partial: /partial verification/i,
  // Anchored on "chain intact within", not a bare "intact within \d+ epochs":
  // the capped+epoched composed line also contains "intact within N epochs"
  // (as "...records intact within 2 epochs from the start..."), and only the
  // pure epoched line opens with the word "chain" immediately before it.
  epoched: /chain intact within \d+ epochs/i,
  tampered: /chain tampered/i,
  error: /could not verify/i,
};

/** Assert exactly one of the five mutually-exclusive result lines is on
 *  screen. Pins the honesty boundary pairwise on every test (present line
 *  found, every OTHER line absent) rather than only positively — a
 *  regression that made two lines render at once would pass a test that
 *  only checked for the expected line's presence. */
function expectOnlyOutcome(present: Outcome): void {
  for (const [outcome, pattern] of Object.entries(LINE_PATTERN) as [Outcome, RegExp][]) {
    if (outcome === present) {
      expect(screen.getByText(pattern)).toBeTruthy();
    } else {
      expect(screen.queryByText(pattern)).toBeNull();
    }
  }
}

beforeEach(() => {
  localStorage.clear();
  vi.mocked(verifyAuditChain).mockReset();
});

describe('Diagnostics — Verify audit chain', () => {
  it('renders the button (admin-side: GET /config itself is require_admin_api, so any Config render is one)', async () => {
    renderDiagnostics();
    expect(await screen.findByRole('button', { name: /verify audit chain/i })).toBeTruthy();
    expect(verifyAuditChain).not.toHaveBeenCalled();
  });

  it('an intact, uncapped chain renders its own success line', async () => {
    vi.mocked(verifyAuditChain).mockResolvedValue(INTACT);
    renderDiagnostics();

    fireEvent.click(await screen.findByRole('button', { name: /verify audit chain/i }));

    expect(await screen.findByText(/chain intact/i)).toBeTruthy();
    expect(screen.getByText(/42 records verified/i)).toBeTruthy();
    expect(verifyAuditChain).toHaveBeenCalledTimes(1);
    expectOnlyOutcome('intact');
  });

  it('a capped-but-ok scan renders its own partial line, never the full-success line', async () => {
    vi.mocked(verifyAuditChain).mockResolvedValue(CAPPED_INTACT);
    renderDiagnostics();

    fireEvent.click(await screen.findByRole('button', { name: /verify audit chain/i }));

    expect(await screen.findByText(/partial verification/i)).toBeTruthy();
    expect(screen.getByText(/capped/i)).toBeTruthy();
    // No checkmark livery on a partial result — only the full-success line
    // gets the green check; asserting its absence here is the whole point.
    expect(screen.queryByText(/chain intact/i)).toBeNull();
    expectOnlyOutcome('partial');
  });

  it('a capped scan across multiple epochs composes both caveats into the partial line', async () => {
    vi.mocked(verifyAuditChain).mockResolvedValue(CAPPED_AND_EPOCHED);
    renderDiagnostics();

    fireEvent.click(await screen.findByRole('button', { name: /verify audit chain/i }));

    // Still the amber "Partial verification" line — capped keeps precedence,
    // this is not a sixth state — but it names the epoch count rather than
    // silently implying one unbroken (if truncated) chain.
    expect(
      await screen.findByText(/8 records intact within 2 epochs from the start of the chain/i),
    ).toBeTruthy();
    expect(screen.getByText(/capped/i)).toBeTruthy();
    expect(screen.queryByText(/chain intact/i)).toBeNull();
    // And not misread as the pure epoched line either — the two must stay
    // pairwise exclusive even though both mention "intact within N epochs".
    expectOnlyOutcome('partial');
  });

  it('a tampered chain renders its own failure line, never the success or partial line', async () => {
    vi.mocked(verifyAuditChain).mockResolvedValue(TAMPERED);
    renderDiagnostics();

    fireEvent.click(await screen.findByRole('button', { name: /verify audit chain/i }));

    expect(await screen.findByText(/chain tampered/i)).toBeTruthy();
    expect(screen.getByText(/1 of 2 epochs broken/i)).toBeTruthy();
    // Locates WHICH epoch broke, not just the locally-renumbered seq.
    expect(screen.getByText(/seq 17 in epoch 2026-08-01/i)).toBeTruthy();
    // Every epoch after the newest (and only) break verified intact — the
    // actionable answer to "am I sound now".
    expect(screen.getByText(/every epoch after 2026-08-01.*is intact/i)).toBeTruthy();
    // WHAT broke, not just that something did: a duplicated position whose
    // copies each still match their own hash is two writers, not an edit.
    expect(screen.getByText(/2 records claim sequence 17/i)).toBeTruthy();
    expectOnlyOutcome('tampered');
  });

  it('the panel reports the blast radius, not just the first position that broke', async () => {
    // The range showed this endpoint's consumer reading "2 records claim
    // sequence 503" off first_break_detail while the CLI and the notification
    // bell — same ChainVerifyResult — reported six sequences and six extra
    // records. One break, two surfaces, two sizes.
    vi.mocked(verifyAuditChain).mockResolvedValue({
      ...TAMPERED,
      duplicate_seqs: 6,
      extra_records: 6,
      max_claimants: 2,
      altered_records: 0,
      missing_seqs: 0,
      oldest_break_at: '2026-09-02T00:29:51.171220+00:00',
      newest_break_at: '2026-09-07T02:36:46.347817+00:00',
      break_kinds: ['duplicate_seq'],
      blast_radius:
        '6 sequence numbers claimed by more than one record, across 6 extra records. ' +
        'No record was altered: every copy still matches its own hash. ' +
        'Newest affected record 2026-09-07T02:36:46.347817+00:00, ' +
        'oldest 2026-09-02T00:29:51.171220+00:00.',
    });
    renderDiagnostics();

    fireEvent.click(await screen.findByRole('button', { name: /verify audit chain/i }));

    expect(await screen.findByText(/6 sequence numbers/i)).toBeTruthy();
    expect(screen.getByText(/6 extra records/i)).toBeTruthy();
    expect(screen.getByText(/no record was altered/i)).toBeTruthy();
    // The smaller, first-instance sentence must not be what the operator reads.
    expect(screen.queryByText(/2 records claim sequence 17/i)).toBeNull();
    // No doubled full stop where the radius already ends in one.
    expect(screen.queryByText(/\.\./)).toBeNull();
    expectOnlyOutcome('tampered');
  });

  it('two broken epochs report the tally, naming both the oldest and newest break', async () => {
    vi.mocked(verifyAuditChain).mockResolvedValue(TWO_EPOCHS_BROKEN);
    renderDiagnostics();

    fireEvent.click(await screen.findByRole('button', { name: /verify audit chain/i }));

    expect(await screen.findByText(/2 of 5 epochs broken/i)).toBeTruthy();
    expect(
      screen.getByText(/oldest break is at seq 1 in epoch 2026-06-26T21:55:52/i),
    ).toBeTruthy();
    expect(screen.getByText(/newest broken epoch is 2026-06-27T02:13:00/i)).toBeTruthy();
    expect(
      screen.getByText(/every epoch after 2026-06-27T02:13:00.*is intact/i),
    ).toBeTruthy();
    expectOnlyOutcome('tampered');
  });

  it('a broken latest epoch says so loudly instead of offering false reassurance', async () => {
    vi.mocked(verifyAuditChain).mockResolvedValue(LATEST_EPOCH_BROKEN);
    renderDiagnostics();

    fireEvent.click(await screen.findByRole('button', { name: /verify audit chain/i }));

    expect(await screen.findByText(/1 of 3 epochs broken/i)).toBeTruthy();
    expect(screen.getByText(/the latest epoch is broken/i)).toBeTruthy();
    // Nothing intact to point to — the reassurance sentence must not appear.
    expect(screen.queryByText(/epoch after .* is intact/i)).toBeNull();
    expectOnlyOutcome('tampered');
  });

  it('a capped, tampered scan states the tally but claims nothing about epochs it never fetched', async () => {
    vi.mocked(verifyAuditChain).mockResolvedValue(CAPPED_AND_TAMPERED);
    renderDiagnostics();

    fireEvent.click(await screen.findByRole('button', { name: /verify audit chain/i }));

    expect(await screen.findByText(/1 of 2 epochs broken/i)).toBeTruthy();
    expect(screen.getByText(/capped/i)).toBeTruthy();
    // The cap truncates the NEWEST end of the chain — this scan cannot vouch
    // for what it never fetched, in either direction.
    expect(screen.queryByText(/epoch after .* is intact/i)).toBeNull();
    expect(screen.queryByText(/the latest epoch is broken/i)).toBeNull();
    expectOnlyOutcome('tampered');
  });

  it('an all-clear spanning multiple epochs renders its own amber line, never green', async () => {
    vi.mocked(verifyAuditChain).mockResolvedValue(EPOCHED);
    renderDiagnostics();

    fireEvent.click(await screen.findByRole('button', { name: /verify audit chain/i }));

    expect(await screen.findByText(/intact within 3 epochs/i)).toBeTruthy();
    expect(screen.getByText(/9 records/i)).toBeTruthy();
    expect(screen.getByText(/2026-08-17/i)).toBeTruthy();
    // No checkmark livery here either — same reasoning as the capped case,
    // and asserting the exact full-success line's absence is the whole point
    // (a bare /chain intact/i probe would also match this line's own opening
    // words, which is exactly why LINE_PATTERN.intact was tightened).
    expect(screen.queryByText(/chain intact\./i)).toBeNull();
    expectOnlyOutcome('epoched');
  });

  it('a request that errors reads as "could not verify" — distinct from intact, partial, and tampered', async () => {
    vi.mocked(verifyAuditChain).mockRejectedValue(new Error('Forbidden'));
    renderDiagnostics();

    fireEvent.click(await screen.findByRole('button', { name: /verify audit chain/i }));

    expect(await screen.findByText(/could not verify/i)).toBeTruthy();
    expect(screen.getByText(/forbidden/i)).toBeTruthy();
    expectOnlyOutcome('error');
  });
});
