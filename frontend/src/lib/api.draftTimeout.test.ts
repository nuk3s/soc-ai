// Wire contract for the two draft-detection calls (dogfood 1.3 F1): a draft is
// one synchronous heavy-model call measured at 16–44s live, so both MUST carry
// an explicit generous budget instead of inheriting the 20s default — which
// timed the client out every single time while the server finished (and then
// discarded) a good draft.
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { draftFindingDetection, draftInvestigationDetection } from './api';

let fetchMock: ReturnType<typeof vi.fn>;
let timeoutSpy: MockInstance<typeof AbortSignal.timeout>;

const ok = (body: unknown = {}) =>
  Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) } as Response);

beforeEach(() => {
  fetchMock = vi.fn(() => ok());
  vi.stubGlobal('fetch', fetchMock);
  timeoutSpy = vi.spyOn(AbortSignal, 'timeout');
});

afterEach(() => {
  timeoutSpy.mockRestore();
  vi.unstubAllGlobals();
});

const url = (): string => String(fetchMock.mock.calls[0][0]);
const init = (): RequestInit => fetchMock.mock.calls[0][1] as RequestInit;

describe('draftFindingDetection', () => {
  it('POSTs the draft path with a budget sized for the heavy model, not the 20s default', async () => {
    await draftFindingDetection('01HUNTX', 2);
    expect(url()).toBe('/api/v1/hunts/01HUNTX/findings/2/draft-detection');
    expect(init().method).toBe('POST');
    expect(timeoutSpy).toHaveBeenCalledWith(180_000);
  });

  it('URL-encodes a hostile hunt id rather than forging a path', async () => {
    await draftFindingDetection('a/b', 0);
    expect(url()).toBe('/api/v1/hunts/a%2Fb/findings/0/draft-detection');
  });
});

describe('draftInvestigationDetection', () => {
  it('POSTs the investigation draft path with the same generous budget', async () => {
    await draftInvestigationDetection('INV-9');
    expect(url()).toBe('/api/v1/investigations/INV-9/draft-detection');
    expect(init().method).toBe('POST');
    expect(timeoutSpy).toHaveBeenCalledWith(180_000);
  });
});
