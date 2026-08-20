// The audit-chain verify control — the Diagnostics panel's third probe,
// alongside Test ES / Test LLM. This is what makes the Operate hub's
// "Audit chain" card promise real (soc_ai/api/webui/routes_config.py:
// GET /config/audit/verify-chain).
//
// The endpoint is explicitly NOT fail-soft (its own docstring: it raises on
// an unreachable or partially-read index rather than answering), and a
// capped-but-ok scan is its own honesty boundary too (verify.py's module
// docstring: "a capped scan cannot claim the whole chain was verified... the
// caller MUST surface it"). So there are FOUR outcomes, not two, each with
// its own line: intact (green ✓), partial (amber ⚠ — capped+ok, no
// checkmark), tampered (red ✗), and "could not verify" (amber ⚠ — a request
// failure, distinct from a partial-but-ran verification). A false all-clear
// outranks any 500, and a false tamper alarm is nearly as costly, so none of
// the four may ever be rendered as another — `expectOnlyOutcome` below pins
// that pairwise on every test, not just positively.
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
  checked_at: '2026-08-19T10:00:00+00:00',
};

// Capped+ok: the scan hit soc_ai/audit/verify.py's max_records cap before
// exhausting the index. It genuinely covers only a PREFIX of the chain (the
// oldest records — the paging sort is `seq ASCENDING`), so `ok: true` here
// must not read as a full clean bill of health.
const CAPPED_INTACT: AuditChainVerifyResult = {
  ok: true,
  records_verified: 500_000,
  first_broken_seq: null,
  first_seq: 1,
  last_seq: 500_000,
  capped: true,
  checked_at: '2026-08-19T10:00:00+00:00',
};

const TAMPERED: AuditChainVerifyResult = {
  ok: false,
  records_verified: 42,
  first_broken_seq: 17,
  first_seq: 1,
  last_seq: 42,
  capped: false,
  checked_at: '2026-08-19T10:00:00+00:00',
};

type Outcome = 'intact' | 'partial' | 'tampered' | 'error';

const LINE_PATTERN: Record<Outcome, RegExp> = {
  intact: /chain intact/i,
  partial: /partial verification/i,
  tampered: /chain tampered/i,
  error: /could not verify/i,
};

/** Assert exactly one of the four mutually-exclusive result lines is on
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

  it('a tampered chain renders its own failure line, never the success or partial line', async () => {
    vi.mocked(verifyAuditChain).mockResolvedValue(TAMPERED);
    renderDiagnostics();

    fireEvent.click(await screen.findByRole('button', { name: /verify audit chain/i }));

    expect(await screen.findByText(/chain tampered/i)).toBeTruthy();
    expect(screen.getByText(/seq 17/i)).toBeTruthy();
    expectOnlyOutcome('tampered');
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
