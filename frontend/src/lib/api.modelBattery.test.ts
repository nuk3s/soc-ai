// Wire contract for the model-battery calls. startModelBattery used to hand
// request() a JSON string without a Content-Type: a browser then labels the
// body text/plain, FastAPI refuses to parse it as JSON and answers 422 — so
// "Run the full check" never started anything, and the screen swallowed the
// rejection. The screen tests mock this function and the backend tests post
// with a proper header, so only a test on the wire shape itself catches it.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getModelBattery, startModelBattery } from './api';

let fetchMock: ReturnType<typeof vi.fn>;

const ok = (body: unknown = {}) =>
  Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) } as Response);

beforeEach(() => {
  fetchMock = vi.fn(() => ok());
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const url = (): string => String(fetchMock.mock.calls[0][0]);
const init = (): RequestInit => fetchMock.mock.calls[0][1] as RequestInit;
const headers = (): Record<string, string> => init().headers as Record<string, string>;

describe('startModelBattery', () => {
  it('POSTs a JSON body labelled as JSON, so the server parses it', async () => {
    await startModelBattery('analyst-model-x');
    expect(url()).toBe('/api/v1/config/model-battery');
    expect(init().method).toBe('POST');
    expect(headers()['Content-Type']).toBe('application/json');
    expect(JSON.parse(String(init().body))).toEqual({ model: 'analyst-model-x' });
  });

  it('returns the server acknowledgement', async () => {
    fetchMock.mockReturnValueOnce(ok({ started: true, model: 'analyst-model-x' }));
    await expect(startModelBattery('analyst-model-x')).resolves.toEqual({
      started: true,
      model: 'analyst-model-x',
    });
  });
});

describe('getModelBattery', () => {
  it('GETs the status for the model, URL-encoded', async () => {
    await getModelBattery('vendor/model:8b');
    expect(url()).toBe('/api/v1/config/model-battery?model=vendor%2Fmodel%3A8b');
    expect(init().method).toBeUndefined();
  });
});
