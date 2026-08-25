// Draft-detection affordance + review pane (1.3 slice 3, "the detection
// bridge") on the Investigation screen. A promoted hunt finding that landed a
// confirmed TP verdict can be turned into a Sigma rule the analyst reviews,
// edits, and EXPORTS — copy/download only, no deploy. The button is gated on
// THREE finding-shape conditions (hunt-kind, complete, true_positive) AND the
// `sigma_authoring_enabled` about-flag, mirroring how the Dashboard assistant
// gates on `general_chat_enabled` (Dashboard.generalChat.test.tsx) — except
// this flag defaults OFF, so absence must mean hidden.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AboutInfo, Investigation as Inv, SigmaDraft } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn(),
  draftInvestigationDetection: vi.fn(),
}));

import { draftInvestigationDetection, getAbout } from '../lib/api';
import { Investigation } from './Investigation';

const about = (sigmaOn: boolean): AboutInfo => ({
  version: '1.0.0',
  repo_url: 'https://example.test/soc-ai',
  license: 'MIT',
  update_check_enabled: false,
  general_chat_enabled: true,
  sigma_authoring_enabled: sigmaOn,
});

const baseInv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'Zerologon-shaped dce_rpc burst',
    kind: 'hunt',
    host: '192.168.10.20',
    ip: '192.168.10.20',
    verdict: 'true_positive',
    conf: 0.86,
    rationale: 'Confirmed Netlogon spoof attempt against DC01.',
    summary: [{ t: 'text', v: 'evidence' }],
    status: 'complete',
    elapsedLabel: '4m 5s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    huntId: '01HUNTABC000000000000000000',
    huntObjective: 'Sweep for Zerologon-shaped Netlogon spoofing',
    ...over,
  }) as Inv;

const sigmaDraft = (over: Partial<SigmaDraft> = {}): SigmaDraft => ({
  title: 'DC01 dce_rpc NetrServerAuthenticate3 burst',
  sigma_yaml:
    'title: DC01 dce_rpc burst\nlogsource:\n  category: dce_rpc\ndetection:\n  selection:\n    dce_rpc.operation: NetrServerAuthenticate3\n  condition: selection\n',
  oql: 'event.dataset:zeek.dce_rpc AND zeek.dce_rpc.operation:NetrServerAuthenticate3',
  rationale: "Fires on the same Netlogon operation sequence the finding's evidence cited.",
  validator_note: null,
  schema_ok: true,
  dry_run: {
    ran: true,
    hit_count: 4,
    total_is_lower_bound: false,
    sample_ids: ['tel-doc-000001', 'tel-doc-000002'],
    window_days: 30,
    error: null,
  },
  ...over,
});

function mount(inv: Inv) {
  return render(
    <MemoryRouter>
      <Investigation inv={inv} layout="page" />
    </MemoryRouter>,
  );
}

describe('draft-detection affordance — visibility gates', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('appears for a hunt-kind, complete, true_positive finding when the flag is on', async () => {
    vi.mocked(getAbout).mockResolvedValue(about(true));
    mount(baseInv({}));
    expect(await screen.findByRole('button', { name: /draft detection/i })).toBeTruthy();
  });

  it('is hidden when sigma_authoring_enabled is off', async () => {
    vi.mocked(getAbout).mockResolvedValue(about(false));
    const inv = baseInv({ rationale: 'flag-off case' });
    mount(inv);
    await screen.findByText('flag-off case');
    expect(screen.queryByRole('button', { name: /draft detection/i })).toBeNull();
  });

  // F21 (1.3 dogfood): the flag is hot-editable, so the one investigation
  // shape that COULD draft a detection points at the switch instead of
  // rendering nothing.
  it('shows a quiet enable-it pointer for a confirmed-TP hunt investigation when the flag is off', async () => {
    vi.mocked(getAbout).mockResolvedValue(about(false));
    mount(baseInv({}));
    const link = await screen.findByRole('link', { name: /enable it in config/i });
    expect(link).toHaveAttribute('href', '/config#triage-automation');
    expect(screen.getByText(/detection authoring is off/i)).toBeTruthy();
  });

  it('does not show the enable-it pointer for a non-hunt investigation with the flag off', async () => {
    vi.mocked(getAbout).mockResolvedValue(about(false));
    const inv = baseInv({ kind: 'suricata', rationale: 'flag-off suricata case', huntId: null, huntObjective: null });
    mount(inv);
    await screen.findByText('flag-off suricata case');
    expect(screen.queryByText(/detection authoring is off/i)).toBeNull();
  });

  it('does not show the enable-it pointer for a non-TP hunt investigation with the flag off', async () => {
    vi.mocked(getAbout).mockResolvedValue(about(false));
    const inv = baseInv({ verdict: 'false_positive', rationale: 'flag-off non-tp case' });
    mount(inv);
    await screen.findByText('flag-off non-tp case');
    expect(screen.queryByText(/detection authoring is off/i)).toBeNull();
  });

  it('is hidden for a non-hunt-kind investigation even with the flag on', async () => {
    vi.mocked(getAbout).mockResolvedValue(about(true));
    const inv = baseInv({ kind: 'suricata', rationale: 'non-hunt case', huntId: null, huntObjective: null });
    mount(inv);
    await screen.findByText('non-hunt case');
    expect(screen.queryByRole('button', { name: /draft detection/i })).toBeNull();
  });

  it('is hidden for a non-true_positive verdict', async () => {
    vi.mocked(getAbout).mockResolvedValue(about(true));
    const inv = baseInv({ verdict: 'false_positive', rationale: 'non-tp case' });
    mount(inv);
    await screen.findByText('non-tp case');
    expect(screen.queryByRole('button', { name: /draft detection/i })).toBeNull();
  });

  it('is hidden while the investigation is not yet complete', async () => {
    vi.mocked(getAbout).mockResolvedValue(about(true));
    const inv = baseInv({ status: 'investigating', rationale: 'still-running case' });
    mount(inv);
    await screen.findByText('still-running case');
    expect(screen.queryByRole('button', { name: /draft detection/i })).toBeNull();
  });
});

describe('draft-detection review pane', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about(true));
  });

  it('calls draftInvestigationDetection and renders the rule, the dry-run line, and export-only controls', async () => {
    vi.mocked(draftInvestigationDetection).mockResolvedValue(sigmaDraft());
    const inv = baseInv({});
    mount(inv);

    const btn = await screen.findByRole('button', { name: /draft detection/i });
    fireEvent.click(btn);

    await waitFor(() => expect(draftInvestigationDetection).toHaveBeenCalledWith(inv.id));
    expect(await screen.findByText(/would have fired 4×/i)).toBeTruthy();
    expect(screen.getByText('DC01 dce_rpc NetrServerAuthenticate3 burst')).toBeTruthy();
    expect(screen.getByText('Rule structure valid')).toBeTruthy();
    expect(screen.getByRole('button', { name: /copy rule/i })).toBeTruthy();
    expect(screen.getByRole('button', { name: /download \.yml/i })).toBeTruthy();
    // No deploy/apply-to-SO affordance — export only.
    expect(screen.queryByRole('button', { name: /deploy/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /apply/i })).toBeNull();
  });

  it('Copy rule exports the analyst-edited YAML, not the server original', async () => {
    // The textarea promises "edit before export"; Copy must honour that edit,
    // not silently paste the pre-edit rule into Security Onion (the asymmetry
    // caught in Task 6 review — Download used the edit, Copy did not).
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    vi.mocked(draftInvestigationDetection).mockResolvedValue(sigmaDraft());
    mount(baseInv({}));

    fireEvent.click(await screen.findByRole('button', { name: /draft detection/i }));
    const textarea = (await screen.findByLabelText(/sigma rule \(yaml\)/i)) as HTMLTextAreaElement;
    fireEvent.change(textarea, { target: { value: 'title: EDITED BY ANALYST\n' } });

    fireEvent.click(screen.getByRole('button', { name: /copy rule/i }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('title: EDITED BY ANALYST\n'));
    expect(writeText).not.toHaveBeenCalledWith(sigmaDraft().sigma_yaml);
  });

  it('renders the honest "couldn\'t run" message when the dry run could not run', async () => {
    vi.mocked(draftInvestigationDetection).mockResolvedValue(
      sigmaDraft({
        dry_run: {
          ran: false,
          hit_count: 0,
          total_is_lower_bound: false,
          sample_ids: [],
          window_days: 30,
          error: 'The Security Onion grid is slow or unreachable',
        },
      }),
    );
    mount(baseInv({}));
    fireEvent.click(await screen.findByRole('button', { name: /draft detection/i }));

    expect(
      await screen.findByText(/Dry run couldn't run: The Security Onion grid is slow or unreachable/i),
    ).toBeTruthy();
    expect(screen.queryByText(/would have fired/i)).toBeNull();
  });

  it('renders the validator_note when the schema check failed', async () => {
    vi.mocked(draftInvestigationDetection).mockResolvedValue(
      sigmaDraft({
        schema_ok: false,
        validator_note: 'Sigma rule missing required keys (title/logsource/detection).',
      }),
    );
    mount(baseInv({}));
    fireEvent.click(await screen.findByRole('button', { name: /draft detection/i }));

    expect(
      await screen.findByText('Sigma rule missing required keys (title/logsource/detection).'),
    ).toBeTruthy();
    expect(screen.queryByText('Rule structure valid')).toBeNull();
  });

  // F12 (1.3 dogfood): on this exact screen the toolbar's decision-record
  // download and the pane's Sigma download sit together — a control reading
  // just "Export" beside "Download .yml" reads as the same artifact.
  it('names the toolbar export by its artifact so it cannot be mistaken for the Sigma download', async () => {
    vi.mocked(draftInvestigationDetection).mockResolvedValue(sigmaDraft());
    mount(baseInv({}));
    fireEvent.click(await screen.findByRole('button', { name: /draft detection/i }));
    await screen.findByRole('button', { name: /download \.yml/i });

    expect(screen.getByRole('button', { name: /export decision record/i })).toBeTruthy();
    // No control left reading just "Export".
    expect(screen.queryByRole('button', { name: /^export$/i })).toBeNull();
  });

  it('surfaces a rejected draft request as an honest error, not a silent no-op', async () => {
    vi.mocked(draftInvestigationDetection).mockRejectedValue(
      new Error('The detection bridge is disabled — enable it in the config console.'),
    );
    mount(baseInv({}));
    fireEvent.click(await screen.findByRole('button', { name: /draft detection/i }));

    expect(await screen.findByText(/detection bridge is disabled/i)).toBeTruthy();
  });
});
