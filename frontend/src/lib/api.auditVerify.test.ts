// verifyAuditChain() — and, through it, request()'s generic error-detail
// extraction for the `{reason, message}` shape this ONE endpoint deliberately
// uses instead of the house `{reason, hint}` (soc_ai/api/webui/routes_config.py
// GET /config/audit/verify-chain; the `message` key is pinned server-side by
// tests/test_degraded_grid_panels.py, so the fix belongs here, not there).
//
// Before request()'s `?? body?.detail?.message` fallback, a partial-read
// refusal's shard narrative ("N of M shards failed — the chain cannot be
// verified from a partial read") was flattened to the generic "502 Bad
// Gateway" one layer from the screen — the Diagnostics panel's "Could not
// verify" line never saw the reason. These tests pin the fix and its
// priority order.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { verifyAuditChain } from './api';

let fetchMock: ReturnType<typeof vi.fn>;

const ok = (body: unknown) =>
  Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) } as Response);

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('verifyAuditChain', () => {
  it('resolves with the parsed result on a clean read', async () => {
    fetchMock.mockReturnValue(
      ok({
        ok: true,
        records_verified: 7,
        first_broken_seq: null,
        first_seq: 0,
        last_seq: 6,
        capped: false,
        checked_at: '2026-08-19T10:00:00+00:00',
      }),
    );
    const result = await verifyAuditChain();
    expect(result.ok).toBe(true);
    expect(result.records_verified).toBe(7);
  });

  it('surfaces detail.message when the body carries {reason, message} with no hint', async () => {
    // The verify-chain endpoint's actual partial-read shape — no `hint` key
    // at all, only `message`.
    fetchMock.mockResolvedValue({
      ok: false,
      status: 502,
      statusText: 'Bad Gateway',
      json: () =>
        Promise.resolve({
          detail: {
            reason: 'audit_verify_failed',
            message: '2 of 5 shards failed — the chain cannot be verified from a partial read',
          },
        }),
    } as Response);
    await expect(verifyAuditChain()).rejects.toThrow(/2 of 5 shards failed/);
  });

  it('still prefers detail.hint over detail.message when a body carries both', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 502,
      statusText: 'Bad Gateway',
      json: () =>
        Promise.resolve({
          detail: { reason: 'x', hint: 'the hint wins', message: 'the message loses' },
        }),
    } as Response);
    await expect(verifyAuditChain()).rejects.toThrow(/the hint wins/);
  });

  it('falls back to the generic status line when neither hint nor message is present', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 403,
      statusText: 'Forbidden',
      json: () => Promise.resolve({ detail: { reason: 'not_admin' } }),
    } as Response);
    await expect(verifyAuditChain()).rejects.toThrow(/403 Forbidden/);
  });
});
