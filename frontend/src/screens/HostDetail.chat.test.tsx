// The host page chat dock (task #65): the same bottom-right bubble the
// investigation page carries, scoped to ONE machine. What these pin:
//
//   * the dock mounts on the host page and opens the shared chat panel —
//     labelled with the thread size once there is one;
//   * the scope label is the name a human uses (the resolved hostname) and
//     only falls back to the address when nothing named the host;
//   * sending goes through the host endpoints with the page's ip;
//   * a transport failure renders the honest error bubble, not a hang;
//   * the hunt-proposal card is the SHARED HuntProposalCard — it renders, it
//     never starts a hunt on its own, and confirming it launches and opens the
//     live hunt.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ChatThread } from '../lib/api';
import type { Dossier, DossierField, DossierFieldName } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getDossier: vi.fn(),
  getHostActivity: vi.fn(),
  getMe: vi.fn(),
  // The role datalist's vocabulary GET; resolves empty here (not under test),
  // so the declare editor falls back to ROLE_VOCABULARY.
  getDossierSummary: vi.fn().mockResolvedValue({}),
  getHostChat: vi.fn(),
  postHostChat: vi.fn(),
  clearHostChat: vi.fn(),
  startHuntConsole: vi.fn(),
}));

import {
  clearHostChat,
  getDossier,
  getHostActivity,
  getHostChat,
  getMe,
  postHostChat,
  startHuntConsole,
} from '../lib/api';
import { HostDetail } from './HostDetail';

// TEST-NET-1 (RFC 5737) — never a lab address; the leak gate reads tests too.
const IP = '192.0.2.10';

const FIELD_NAMES: DossierFieldName[] = [
  'hostname',
  'mac',
  'os_family',
  'os_detail',
  'role',
  'services_offered',
  'management_plane',
  'domain_membership',
  'is_static_addressed',
  'activity_profile',
  'criticality',
  'policy_notes',
];

function field(name: DossierFieldName, over: Partial<DossierField> = {}): DossierField {
  return {
    field: name,
    value: null,
    value_json: null,
    source: null,
    confidence: 0,
    strength: 'none',
    reason: 'no_signal',
    overridden: false,
    conflict_kind: null,
    evidence: {},
    observed_at: null,
    first_seen: null,
    last_run_at: null,
    retracted_at: null,
    operator_actor: null,
    operator_note: null,
    operator_set_at: null,
    inferred_value: null,
    inferred_value_json: null,
    inferred_confidence: null,
    inferred_source: null,
    conflict: null,
    ...over,
  };
}

function dossier(
  patch: Partial<Record<DossierFieldName, Partial<DossierField>>> = {},
  over: Partial<Dossier> = {},
): Dossier {
  const fields = FIELD_NAMES.map((name) => field(name, patch[name] ?? {}));
  return {
    ip: IP,
    found: true,
    fields,
    first_seen: '2026-07-01T08:00:00Z',
    last_seen: '2026-08-07T09:00:00Z',
    last_built_at: '2026-08-07T06:00:00Z',
    last_observed_at: '2026-08-07T09:00:00Z',
    event_count: 3662,
    identity_rebound_at: null,
    build_error: null,
    override_count: 0,
    conflict_count: 0,
    reporting: false,
    ...over,
  };
}

/** A host the sweep has named — the scope label should say "web-01". */
const named = () =>
  dossier({
    hostname: {
      value: 'web-01',
      source: 'hostlog',
      confidence: 0.95,
      strength: 'strong',
      reason: null,
    },
  });

type Msg = ChatThread['messages'][number];

const thread = (messages: Msg[], over: Partial<ChatThread> = {}): ChatThread => ({
  messages,
  pending: false,
  ...over,
});

const proposed = (objective: string, why: string): Msg => ({
  role: 'assistant',
  text: 'Nothing alarming in the last hour.',
  messageId: 7,
  kind: 'hunt_proposal',
  applied: false,
  proposal: { objective, why },
});

function Here() {
  const loc = useLocation();
  return <div data-testid="here">{loc.pathname}</div>;
}

const mount = (url = `/hosts/${IP}`) =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <Routes>
        <Route path="/hosts/:ip" element={<HostDetail />} />
        <Route path="*" element={null} />
      </Routes>
      <Here />
    </MemoryRouter>,
  );

const openDock = async () => {
  fireEvent.click(await screen.findByRole('button', { name: /chat/i }));
  return screen.findByPlaceholderText(/ask about this host/i);
};

const send = (text: string) => {
  fireEvent.change(screen.getByPlaceholderText(/ask about this host/i), {
    target: { value: text },
  });
  fireEvent.click(screen.getByLabelText('Send'));
};

beforeEach(() => {
  sessionStorage.clear(); // the chat draft persists per subject
  vi.clearAllMocks();
  vi.mocked(getDossier).mockResolvedValue(named());
  vi.mocked(getHostActivity).mockResolvedValue({
    peers: [],
    volume: [],
    users: null,
    alerts_7d: 0,
    latest_investigation: null,
    peers_truncated: false,
    users_truncated: false,
  });
  vi.mocked(getMe).mockResolvedValue({ username: 'root', role: 'admin', status: '' });
  vi.mocked(getHostChat).mockResolvedValue(thread([]));
  vi.mocked(postHostChat).mockResolvedValue(thread([]));
  vi.mocked(clearHostChat).mockResolvedValue(thread([]));
  vi.mocked(startHuntConsole).mockResolvedValue({ hunt_id: 'H-1' });
});

describe('HostChatDock — mounting on the host page', () => {
  it('floats the launcher on a loaded host page, worded for a first question', async () => {
    mount();
    const launcher = await screen.findByRole('button', { name: /chat about this host/i });
    expect(launcher).toBeTruthy();
  });

  it('counts the existing shared thread on the launcher', async () => {
    // The thread is per-HOST, so a colleague's conversation about this box is
    // this conversation — the label says there is one to read.
    vi.mocked(getHostChat).mockResolvedValue(
      thread([
        { role: 'user', text: 'what is this host?' },
        { role: 'assistant', text: 'A web server.' },
      ]),
    );
    mount();
    expect(await screen.findByRole('button', { name: /chat · 2/i })).toBeTruthy();
  });

  it('opens the panel scoped to the resolved hostname', async () => {
    mount();
    await openDock();
    expect(screen.getByText('Chat about this host')).toBeTruthy();
    // The panel header's scope label (the hero also says "web-01", so pick the
    // faint mono label rather than any mention).
    const scope = screen
      .getAllByText('web-01')
      .filter((el) => el.className.includes('text-faint'));
    expect(scope.length).toBe(1);
  });

  it('falls back to the address when nothing has named the host', async () => {
    vi.mocked(getDossier).mockResolvedValue(dossier());
    mount();
    await openDock();
    // The scope label in the panel header — the address is the honest name.
    const scope = screen
      .getAllByText(IP)
      .filter((el) => el.className.includes('text-faint'));
    expect(scope.length).toBeGreaterThan(0);
  });

  it('mounts no dock when the segment is not a host address', async () => {
    vi.mocked(getDossier).mockRejectedValue(new Error('the dossier is keyed on IP addresses'));
    mount('/hosts/not-a-host');
    await screen.findByText(/not an IP address/i);
    expect(screen.queryByRole('button', { name: /chat/i })).toBeNull();
  });
});

describe('HostChatDock — the send flow', () => {
  it('sends through the host endpoints with the page ip and renders the reply', async () => {
    vi.mocked(postHostChat).mockResolvedValue(
      thread([
        { role: 'user', text: 'who has it talked to today?' },
        { role: 'assistant', text: 'Three peers, all internal.' },
      ]),
    );
    mount();
    await openDock();
    send('who has it talked to today?');

    expect(await screen.findByText('Three peers, all internal.')).toBeTruthy();
    expect(vi.mocked(postHostChat).mock.calls[0]).toEqual([IP, 'who has it talked to today?']);
  });

  it('renders the honest error bubble when the transport fails, not a hang', async () => {
    vi.mocked(postHostChat).mockRejectedValue(new Error('boom'));
    mount();
    await openDock();
    send('what is this host?');

    expect(await screen.findByText(/could not reach the server/i)).toBeTruthy();
  });

  it('clears only after asking, and re-reads the thread', async () => {
    vi.mocked(getHostChat).mockResolvedValue(
      thread([{ role: 'assistant', text: 'A web server.' }]),
    );
    mount();
    await openDock();
    await screen.findByText('A web server.');

    vi.mocked(getHostChat).mockResolvedValue(thread([]));
    fireEvent.click(screen.getByRole('button', { name: /clear conversation/i }));

    await waitFor(() => expect(clearHostChat).toHaveBeenCalledWith(IP));
    expect(await screen.findByText(/answered here from its dossier/i)).toBeTruthy();
  });
});

describe('HostChatDock — the shared hunt-proposal card', () => {
  it('renders the proposal beside the prose and never starts it alone', async () => {
    vi.mocked(getHostChat).mockResolvedValue(
      thread([proposed(`Sweep zeek.conn for every peer of ${IP} over 7d`, 'a week needs a sweep')]),
    );
    mount();
    await openDock();

    expect(
      await screen.findByText(`Sweep zeek.conn for every peer of ${IP} over 7d`),
    ).toBeTruthy();
    expect(screen.getByText('a week needs a sweep')).toBeTruthy();
    // The prose half of the reply survives alongside the card.
    expect(screen.getByText('Nothing alarming in the last hour.')).toBeTruthy();
    expect(startHuntConsole).not.toHaveBeenCalled();
  });

  it('starts the hunt on confirm and opens it', async () => {
    vi.mocked(getHostChat).mockResolvedValue(
      thread([proposed('Sweep zeek.conn over 7d', 'why')]),
    );
    mount();
    await openDock();
    fireEvent.click(await screen.findByRole('button', { name: /start.*hunt/i }));

    expect(startHuntConsole).toHaveBeenCalledWith('Sweep zeek.conn over 7d');
    await waitFor(() => expect(screen.getByTestId('here').textContent).toBe('/hunts/H-1'));
  });

  it('keeps the analyst on the host page when the hunt will not start', async () => {
    vi.mocked(getHostChat).mockResolvedValue(
      thread([proposed('Sweep zeek.conn over 7d', 'why')]),
    );
    vi.mocked(startHuntConsole).mockRejectedValue(new Error('hunts are disabled'));
    mount();
    await openDock();
    fireEvent.click(await screen.findByRole('button', { name: /start.*hunt/i }));

    expect(await screen.findByText(/hunts are disabled/)).toBeTruthy();
    expect(screen.getByTestId('here').textContent).toBe(`/hosts/${IP}`);
  });
});
