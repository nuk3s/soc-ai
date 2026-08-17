// Two pages used to answer for an address: /entity/:value ("what have we
// RECORDED about this thing") and /hosts/:ip ("what IS it"). Keeping both meant
// every pivot in the app had to pick one, and the one an analyst landed on
// decided what they were told about the same machine. The host page absorbed
// the entity view's answer, so an IP key now redirects into it and Entity keeps
// only the keys /hosts cannot serve — domains, users, hashes, which the dossier
// is not keyed on and 404s.
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

beforeEach(() => {
  // Everything fails like an unreachable backend; each screen lands on its own
  // error state, which is beside the point — the route is proven by the request
  // having been ATTEMPTED.
  fetchMock = vi.fn(() => Promise.reject(new TypeError('offline')));
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

describe('/entity/:value — an address belongs to the host page', () => {
  it('sends an INTERNAL IPv4 key to the merged host page', async () => {
    // RFC1918, because that is the only space the dossier census populates.
    renderAt('/entity/192.168.10.202');
    await waitFor(() => expect(asked('/api/v1/dossiers/192.168.10.202')).toBe(true));
    // And does not load the page it redirected away from on the way past.
    expect(asked('/api/v1/entity/')).toBe(false);
  });

  it('sends an internal IPv6 key there too', async () => {
    // The dossier is keyed through `ipaddress`, which takes both families — a
    // v6 host would otherwise be the one internal address with no host page.
    renderAt('/entity/fd00::5');
    await waitFor(() => expect(asked('/api/v1/dossiers/fd00%3A%3A5')).toBe(true));
  });

  it('leaves a PUBLIC address on Entity, which is the only page that can answer', async () => {
    // The host dossier is internal-CIDR-only by construction (the census gates
    // on `_is_internal_ip`), so a public address is guaranteed `found:false` —
    // and that card says "there is nothing to report about it", which is false
    // whenever the entity timeline holds investigations or hunt findings naming
    // that IP. That is precisely the C2-destination case, and Entity is the only
    // merged investigations + hunt-findings view an address has.
    renderAt('/entity/198.51.100.7');
    await waitFor(() => expect(asked('/api/v1/entity/198.51.100.7')).toBe(true));
    expect(asked('/api/v1/dossiers')).toBe(false);
  });

  it('leaves a public IPv6 address on Entity too', async () => {
    renderAt('/entity/2001:db8::1');
    await waitFor(() => expect(asked('/api/v1/entity/')).toBe(true));
    expect(asked('/api/v1/dossiers')).toBe(false);
  });

  it('still renders Entity for a key the dossier cannot be keyed on', async () => {
    renderAt('/entity/example.com');
    await waitFor(() => expect(asked('/api/v1/entity/example.com')).toBe(true));
    expect(asked('/api/v1/dossiers')).toBe(false);
  });

  it('does not mistake a dotted string for an address', async () => {
    // An octet over 255 is not an address, and redirecting it would land the
    // analyst on the dossier's "that is not an IP" card instead of on the
    // timeline that does have something to say.
    renderAt('/entity/192.0.2.999');
    await waitFor(() => expect(asked('/api/v1/entity/192.0.2.999')).toBe(true));
    expect(asked('/api/v1/dossiers')).toBe(false);
  });
});
