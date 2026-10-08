// /entity/:value is where every entity link lands (dogfood 2026-10-06, S1 and
// S2). The route sent each private address to the host page before anything
// was read, so an address an investigation named that no machine holds opened
// "the network sweep has never seen this address", one more click away from
// the investigations that named it. The entity page now asks which machine
// holds the value: a machine opens its page, any other value stays.
//
// The assertions key on the REQUEST each screen makes rather than on its copy:
// that is what proves which screen actually mounted, and it survives a rewrite
// of either page's markup.
import { render, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { ShellProvider } from './shell/ShellContext';

let fetchMock: ReturnType<typeof vi.fn>;
/** The machine key /hosts/resolve answers with, or null for a 404. */
let holder: string | null = null;

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

beforeEach(() => {
  holder = null;
  fetchMock = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.startsWith('/api/v1/hosts/resolve')) {
      return Promise.resolve(
        holder
          ? json(200, { key: holder, primary_ip: '192.0.2.10', matched: 'address' })
          : json(404, { detail: { reason: 'no_host', message: 'No machine holds this value.' } }),
      );
    }
    // Everything else fails like an unreachable backend; each screen lands on
    // its own error state, which is beside the point.
    return Promise.reject(new TypeError('offline'));
  });
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ShellProvider>
        <App />
      </ShellProvider>
    </MemoryRouter>,
  );
}

const asked = (prefix: string): boolean =>
  fetchMock.mock.calls.some((call) => String(call[0]).startsWith(prefix));

describe('/entity/:value: a machine opens its page, any other value stays', () => {
  it('sends an internal address a machine holds to the machine page', async () => {
    holder = 'agent:a1';
    renderAt('/entity/192.168.10.202');
    await waitFor(() => expect(asked('/api/v1/hosts/agent%3Aa1')).toBe(true));
  });

  it('keeps an internal address no machine holds on the entity page', async () => {
    // Dogfood 2026-10-06, S2: the address an investigation named was in no
    // Hosts row. Its page is the entity page, never the never-seen card.
    renderAt('/entity/192.168.10.226');
    await waitFor(() => expect(asked('/api/v1/entity/192.168.10.226')).toBe(true));
    await waitFor(() => expect(asked('/api/v1/hosts/resolve')).toBe(true));
    expect(asked('/api/v1/dossiers/192.168.10.226')).toBe(false);
  });

  it('keeps a public address on the entity page', async () => {
    renderAt('/entity/198.51.100.7');
    await waitFor(() => expect(asked('/api/v1/entity/198.51.100.7')).toBe(true));
    expect(asked('/api/v1/dossiers')).toBe(false);
  });

  it('keeps a public IPv6 address on the entity page too', async () => {
    renderAt('/entity/2001:db8::1');
    await waitFor(() => expect(asked('/api/v1/entity/')).toBe(true));
    expect(asked('/api/v1/dossiers')).toBe(false);
  });

  it('never asks for the machine of a user', async () => {
    // NEGATIVE CONTROL: the user hint skips the machine read.
    holder = 'agent:a1';
    renderAt('/entity/backup?type=user');
    await waitFor(() => expect(asked('/api/v1/entity/backup?type=user')).toBe(true));
    expect(asked('/api/v1/hosts/resolve')).toBe(false);
  });
});
