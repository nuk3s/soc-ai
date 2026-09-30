import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getTlsStatus: vi.fn(),
}));

import { getTlsStatus } from '../lib/api';
import type { TlsStatus } from '../lib/api';
import { TlsPanel } from './TlsPanel';

const DIRECT: TlsStatus = {
  mode: 'direct',
  cert_path: '/etc/soc-ai/cert.pem',
  key_path: '/etc/soc-ai/key.pem',
  subject: 'CN=soc-ai.example.test',
  issuer: 'CN=Example CA',
  sans: ['soc-ai.example.test'],
  not_before: '2026-09-01T00:00:00+00:00',
  not_after: '2026-12-01T00:00:00+00:00',
  days_left: 62,
  expired: false,
  expiry_band: null,
  self_signed: false,
  chain_length: 2,
  chain_ok: true,
  key_matches: true,
  fingerprint_sha256: 'ab12',
  warnings: [],
  errors: [],
  loaded_at: '2026-09-29T12:00:00+00:00',
  restart_required: false,
};

function mount() {
  return render(
    <MemoryRouter>
      <TlsPanel />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('TlsPanel', () => {
  it('states the certificate, its names and its expiry', async () => {
    vi.mocked(getTlsStatus).mockResolvedValue(DIRECT);
    mount();
    expect(await screen.findByText('CN=soc-ai.example.test')).toBeTruthy();
    expect(screen.getByText(/62 days/)).toBeTruthy();
    expect(screen.getByText('soc-ai.example.test')).toBeTruthy();
    expect(screen.getByText(/issued by CN=Example CA/)).toBeTruthy();
    expect(screen.getByText('2 certificates')).toBeTruthy();
    expect(screen.getByText('matches')).toBeTruthy();
    expect(screen.getByText('2026-09-29 12:00 UTC')).toBeTruthy();
    expect(screen.queryByText(/Restart soc-ai/)).toBeNull();
  });

  it('says the key is not checked when the backend did not compare it', async () => {
    vi.mocked(getTlsStatus).mockResolvedValue({ ...DIRECT, key_matches: null });
    mount();
    expect(await screen.findByText('not checked')).toBeTruthy();
  });

  it('says expired, not a negative day count, past the expiry date', async () => {
    vi.mocked(getTlsStatus).mockResolvedValue({ ...DIRECT, days_left: -3, expired: true });
    mount();
    expect(await screen.findByText(/\(expired\)/)).toBeTruthy();
    expect(screen.queryByText(/-3 days/)).toBeNull();
  });

  it('counts one day in the singular', async () => {
    vi.mocked(getTlsStatus).mockResolvedValue({ ...DIRECT, days_left: 1, expiry_band: 7 });
    mount();
    expect(await screen.findByText(/\(1 day\)/)).toBeTruthy();
  });

  it('names the reason when there is no subject', async () => {
    vi.mocked(getTlsStatus).mockResolvedValue({
      ...DIRECT,
      subject: null,
      issuer: null,
      sans: [],
      chain_length: 0,
      key_matches: null,
      loaded_at: null,
      errors: ['the certificate file is not PEM'],
    });
    mount();
    expect(await screen.findByText('Certificate not read')).toBeTruthy();
    expect(screen.getByText(/not PEM/)).toBeTruthy();
    expect(screen.getByText('Error:')).toBeTruthy();
    expect(screen.getAllByText('none').length).toBe(2);
    expect(screen.getByText('unknown')).toBeTruthy();
  });

  it('says a restart is needed when the files on disk differ from the loaded ones', async () => {
    vi.mocked(getTlsStatus).mockResolvedValue({ ...DIRECT, restart_required: true });
    mount();
    expect(await screen.findByText(/Restart soc-ai to load them/)).toBeTruthy();
    expect(screen.getByText('docker compose restart soc-ai')).toBeTruthy();
    expect(screen.getByText('sudo systemctl restart soc-ai')).toBeTruthy();
  });

  it('shows warnings and errors in their own tone, and Check again reads again', async () => {
    vi.mocked(getTlsStatus).mockResolvedValue({
      ...DIRECT,
      self_signed: true,
      days_left: 6,
      expiry_band: 7,
      warnings: ['the certificate expires in 6 days', 'the certificate is self-signed. Browsers warn on it.'],
    });
    mount();
    expect(await screen.findByText(/expires in 6 days/)).toBeTruthy();
    expect(screen.getAllByText('Warning:').length).toBe(2);
    expect(screen.getByText(/self-signed$/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Check again' }));
    await waitFor(() => expect(vi.mocked(getTlsStatus).mock.calls.length).toBe(2));
    expect(await screen.findByText(/Checked at \d\d:\d\d:\d\d UTC\./)).toBeTruthy();
  });

  it('reads the proxy path when TLS is off', async () => {
    vi.mocked(getTlsStatus).mockResolvedValue({ ...DIRECT, mode: 'off', subject: null, sans: [], days_left: null });
    mount();
    expect(await screen.findByText(/TLS is off/)).toBeTruthy();
    expect(screen.getByText(/proxy/)).toBeTruthy();
  });
});
