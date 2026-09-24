// Task 8 (finding-promotion, 1.3 slice 1) — the Investigate button on a hunt
// finding card. It's the authoring bridge's entry point: promoteFinding turns
// a hunt's cited evidence into a real investigation (idempotent server-side —
// a re-click on an already-promoted finding lands on the same investigation).
// A finding the citation gate stripped down to zero citations has nothing to
// promote, so its button is disabled rather than firing a doomed 422.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AboutInfo, HuntDetailData } from '../lib/types';

const { navigate } = vi.hoisted(() => ({ navigate: vi.fn() }));

vi.mock('react-router-dom', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-router-dom')>()),
  useNavigate: () => navigate,
}));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunt: vi.fn(),
  promoteFinding: vi.fn(),
  cancelHuntConsole: vi.fn(),
  deleteHunt: vi.fn(),
  startHuntConsole: vi.fn(),
  getHuntChat: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  postHuntChat: vi.fn(),
  getAbout: vi.fn(),
  draftFindingDetection: vi.fn(),
  getHunts: vi.fn(),
  getLead: vi.fn(),
  getEvent: vi.fn(),
}));

import {
  draftFindingDetection,
  getAbout,
  getHunt,
  getHunts,
  getLead,
  promoteFinding,
} from '../lib/api';
import { CHIP_LEAD, DISPOSITION, STATUS_COMPLETE } from '../lib/tooltips';
import { HuntDetail } from './HuntDetail';

const about = (sigmaOn: boolean): AboutInfo => ({
  version: '1.0.0',
  repo_url: 'https://example.test/soc-ai',
  license: 'MIT',
  update_check_enabled: false,
  general_chat_enabled: true,
  sigma_authoring_enabled: sigmaOn,
});

const HUNT_ID = 'H-1';

const f0 = {
  title: 'Beaconing to a rare external IP',
  detail: 'Regular 60s-interval callbacks from 192.168.10.15 to 203.0.113.9.',
  severity: 'high',
  category: 'threat',
  hosts: ['192.168.10.15'],
  citations: ['tel-doc-000001'],
};

const f1 = {
  title: 'Unusual outbound DNS volume',
  detail: 'A spike in DNS query volume with no citation the gate could resolve.',
  severity: 'medium',
  category: 'threat',
  hosts: [],
  citations: [] as string[],
};

// Already promoted, verdict landed — the card shows Open + a verdict chip
// instead of a re-clickable Investigate (dogfood fix: the analyst got no
// signal the finding already has a verdict).
const f2 = {
  title: 'Credential dump on DC01',
  detail: 'lsass.exe accessed by an unsigned process.',
  severity: 'critical',
  category: 'threat',
  hosts: ['192.168.10.20'],
  citations: ['tel-doc-000003'],
  // conf deliberately distinct from the hunt-level confidence (0.72) in the
  // fixture below, so the chip's number can be asserted unambiguously.
  investigation: { id: 'inv-9', status: 'complete', verdict: 'false_positive', conf: 0.81 },
};

// Already promoted, still running — the card shows "Investigating…" and
// clicking goes straight to the in-flight investigation (no re-promote).
const f3 = {
  title: 'Unusual RDP fan-out',
  detail: 'One host RDPs to 12 peers in under a minute.',
  severity: 'medium',
  category: 'threat',
  hosts: ['192.168.10.30'],
  citations: ['tel-doc-000004'],
  investigation: { id: 'inv-10', status: 'running', verdict: null, conf: null },
};

// Already promoted, but the run errored — an errored/cancelled/interrupted
// promotion frees the re-promote slot server-side (blocks_rehunt only holds
// running/complete), so the card must fall back to a LIVE Investigate button,
// not a dead Open/Investigating… — the non-obvious case the types.ts comment
// on HuntFinding.investigation warns about.
const f4 = {
  title: 'Suspicious PowerShell encoded command',
  detail: 'Base64-encoded payload executed via powershell.exe -enc.',
  severity: 'high',
  category: 'threat',
  hosts: ['192.168.10.40'],
  citations: ['tel-doc-000005'],
  investigation: { id: 'inv-err', status: 'error', verdict: null, conf: null },
};

// Already promoted AND confirmed — the ONLY finding state confirm-first lets
// a detection be drafted from (promoted investigation complete + true_positive).
const f5 = {
  title: 'Confirmed C2 beacon on FIN-07',
  detail: 'Regular 30s callbacks to a known-bad ASN; the promoted investigation confirmed it.',
  severity: 'critical',
  category: 'threat',
  hosts: ['192.168.10.50'],
  citations: ['tel-doc-000006'],
  investigation: { id: 'inv-tp', status: 'complete', verdict: 'true_positive', conf: 0.9 },
};

function huntFixture(findings: HuntDetailData['findings'] = [f0, f1, f2, f3, f4]): HuntDetailData {
  return {
    id: HUNT_ID,
    objective: 'hunt for beaconing to rare external IPs',
    kind: 'chat',
    status: 'complete',
    narrative: '',
    findings,
    affectedHosts: [],
    mitreTechniques: [],
    recommendedActions: [],
    confidence: 0.72,
    startedBy: 'analyst',
    elapsedLabel: '2m 10s',
    elapsedSec: 130,
    ts: '2026-08-23T00:00:00Z',
    timeline: [],
    diff: null,
  };
}

function mount() {
  return render(
    <MemoryRouter initialEntries={[`/hunts/${HUNT_ID}`]}>
      <Routes>
        <Route path="/hunts/:id" element={<HuntDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('HuntDetail — Investigate a finding', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getHunt).mockResolvedValue(huntFixture());
    // Draft-detection defaults off in this describe block — unrelated to
    // promotion, and off is the flag's own default (see AboutInfo).
    vi.mocked(getAbout).mockResolvedValue(about(false));
  });

  it('renders an Investigate button per finding, disabled when there is nothing citable', async () => {
    mount();
    await screen.findByText(f0.title);
    // f0 (never promoted, citable), f1 (never promoted, nothing citable), f4
    // (promoted but errored — slot freed, so it's citable and live too).
    const buttons = screen.getAllByRole('button', { name: /investigate/i });
    expect(buttons).toHaveLength(3);
    expect(buttons[0]).not.toBeDisabled();
    expect(buttons[1]).toBeDisabled();
    // F11: the disabled reason speaks analyst language — what's missing and
    // what that means — with no pipeline jargon ("citation gate").
    expect(buttons[1].getAttribute('title')).toMatch(/no linked evidence events/i);
    expect(buttons[1].getAttribute('title')).not.toMatch(/citation gate/i);
    expect(buttons[2]).not.toBeDisabled();
  });

  it('promotes the cited finding and navigates to the new investigation', async () => {
    vi.mocked(promoteFinding).mockResolvedValue({ investigation_id: 'inv-1' });
    mount();
    await screen.findByText(f0.title);
    const [btn0] = screen.getAllByRole('button', { name: /investigate/i });
    fireEvent.click(btn0);

    await waitFor(() => expect(promoteFinding).toHaveBeenCalledWith(HUNT_ID, 0));
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith('/investigation/inv-1', {
        state: { from: `/hunts/${HUNT_ID}` },
      }),
    );
  });

  it('surfaces a rejected promotion as an error line and re-enables the button', async () => {
    vi.mocked(promoteFinding).mockRejectedValue(
      new Error('No promotable evidence — the citation gate stripped this finding.'),
    );
    mount();
    await screen.findByText(f0.title);
    const [btn0] = screen.getAllByRole('button', { name: /investigate/i });
    fireEvent.click(btn0);

    await screen.findByText(/no promotable evidence/i);
    expect(navigate).not.toHaveBeenCalled();
    expect(btn0).not.toBeDisabled();
    expect(btn0.textContent).not.toMatch(/starting/i);
  });

  // Slice 1 dogfood fix: finding cards show their promotion state instead of
  // always offering "Investigate", even once a verdict already landed.
  //
  // Queried by button role/name, not finding title text: a hunt with hosted
  // findings also renders a lazy-loaded Host–finding map (HuntVisuals) whose
  // SVG repeats each finding's title as a node label, so a bare title-text
  // query is ambiguous once that chart has mounted. Button names are unique.
  // The investigation is a page, so Open is a link. It was a button that
  // navigated, and the address could not be read before the click.
  it('shows Open + a verdict chip for an already-promoted, complete finding, and does not re-promote on click', async () => {
    mount();
    const openLink = await screen.findByRole('link', { name: /^open$/i });
    expect(openLink.getAttribute('href')).toBe('/investigation/inv-9');
    expect(screen.getByText(/false positive/i)).toBeInTheDocument();
    expect(screen.getByText('0.81')).toBeInTheDocument();
    // A link never re-promotes. The button under it did that on a double
    // click, and the server answered with the same investigation.
    fireEvent.click(openLink);
    expect(promoteFinding).not.toHaveBeenCalled();
  });

  it('shows "Investigating…" for an already-promoted, running finding, and links to it', async () => {
    mount();
    const investigatingLink = await screen.findByRole('link', { name: /Investigating…/i });
    expect(investigatingLink.getAttribute('href')).toBe('/investigation/inv-10');
    fireEvent.click(investigatingLink);
    expect(promoteFinding).not.toHaveBeenCalled();
  });

  it('leaves an unpromoted finding free to promote as before, even alongside promoted siblings', async () => {
    vi.mocked(promoteFinding).mockResolvedValue({ investigation_id: 'inv-fresh' });
    mount();
    const [btn0] = await screen.findAllByRole('button', { name: /investigate/i });
    fireEvent.click(btn0);

    await waitFor(() => expect(promoteFinding).toHaveBeenCalledWith(HUNT_ID, 0));
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith('/investigation/inv-fresh', {
        state: { from: `/hunts/${HUNT_ID}` },
      }),
    );
  });

  it('re-offers a live Investigate button for an errored promotion, and promotes normally on click', async () => {
    vi.mocked(promoteFinding).mockResolvedValue({ investigation_id: 'inv-retry' });
    mount();
    // f0, f1, f4 are the only findings that render an "Investigate"-named
    // button (f2/f3 render Open/Investigating…) — f4 is last in the fixture,
    // so it's the third and final match, in DOM order.
    const buttons = await screen.findAllByRole('button', { name: /investigate/i });
    expect(buttons).toHaveLength(3);
    const errBtn = buttons[2];
    expect(errBtn).not.toBeDisabled();
    fireEvent.click(errBtn);

    await waitFor(() => expect(promoteFinding).toHaveBeenCalledWith(HUNT_ID, 4));
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith('/investigation/inv-retry', {
        state: { from: `/hunts/${HUNT_ID}` },
      }),
    );
  });
});

// 1.3 slice 3 + confirm-first (1.3 dogfood F3) — the per-finding "Draft
// detection" badge (export-only, no SO write). TWO gates now: the
// `sigma_authoring_enabled` flag AND a completed true_positive promoted
// investigation on the finding itself. An unpromoted, still-running, errored,
// or false-positive finding gets no draft affordance at all — Investigate/Open
// is how the analyst confirms first.
describe('HuntDetail — Draft detection per finding (confirm-first)', () => {
  // f0 = never promoted, f2 = complete FALSE positive, f3 = still running,
  // f4 = errored promotion, f5 = complete TRUE positive (ordinal 4).
  const findings = [f0, f2, f3, f4, f5];

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getHunt).mockResolvedValue(huntFixture(findings));
  });

  it('hides every Draft badge when the flag is off, and points the confirmed-TP card at Config', async () => {
    vi.mocked(getAbout).mockResolvedValue(about(false));
    mount();
    await screen.findByText(f0.title);
    expect(screen.queryByRole('button', { name: /draft detection/i })).toBeNull();
    // F21: the one card that COULD draft shows a quiet enable-it pointer
    // instead of rendering nothing (the flag is hot-editable). findByRole
    // would throw on >1 match — so this also pins that the non-TP cards
    // (f0/f2/f3/f4) do NOT get the pointer.
    const link = await screen.findByRole('link', { name: /enable it in config/i });
    expect(link).toHaveAttribute('href', '/config#triage-automation');
    expect(screen.getByText(/detection authoring is off/i)).toBeInTheDocument();
  });

  it('shows the badge ONLY on the finding whose promoted investigation is complete + true_positive', async () => {
    vi.mocked(getAbout).mockResolvedValue(about(true));
    mount();
    await screen.findByText(f0.title);
    // Exactly one badge (f5) — none for the no-investigation (f0),
    // false_positive (f2), still-investigating (f3), or errored (f4) cards.
    const badges = await screen.findAllByRole('button', { name: /draft detection/i });
    expect(badges).toHaveLength(1);
    // No Config pointer when the flag is on.
    expect(screen.queryByText(/detection authoring is off/i)).toBeNull();
  });

  it('drafts a detection for the confirmed finding and renders the review pane', async () => {
    vi.mocked(getAbout).mockResolvedValue(about(true));
    vi.mocked(draftFindingDetection).mockResolvedValue({
      title: 'Confirmed C2 beacon on FIN-07',
      sigma_yaml: 'title: Confirmed C2 beacon on FIN-07\nlogsource:\n  category: network_connection\ndetection:\n  selection:\n    dst_asn: 64501\n  condition: selection\n',
      oql: 'event.dataset:zeek.conn AND destination.as.number:64501',
      rationale: "Fires on the same 30s-interval callback pattern this finding's evidence cited.",
      validator_note: null,
      schema_ok: true,
      dry_run: {
        ran: true,
        hit_count: 2,
        total_is_lower_bound: false,
        sample_ids: ['tel-doc-000006'],
        window_days: 30,
        error: null,
      },
    });
    mount();
    await screen.findByText(f0.title);

    // Confirm-first leaves a single badge — the confirmed-TP finding, f5,
    // at ordinal 4 in this fixture.
    const badge = await screen.findByRole('button', { name: /draft detection/i });
    fireEvent.click(badge);

    await waitFor(() => expect(draftFindingDetection).toHaveBeenCalledWith(HUNT_ID, 4));
    expect(await screen.findByText(/would have fired 2×/i)).toBeTruthy();
    expect(screen.getByRole('button', { name: /copy rule/i })).toBeTruthy();
    expect(screen.getByRole('button', { name: /download \.yml/i })).toBeTruthy();
    expect(screen.queryByRole('button', { name: /deploy/i })).toBeNull();
  });
});

// F21 — journey wayfinding: a completed hunt with findings says what the
// cards are FOR (promote → confirm → draft) in one quiet line.
describe('HuntDetail — journey wayfinding line', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about(false));
  });

  it('renders the promote→confirm→draft line on a completed hunt with findings', async () => {
    vi.mocked(getHunt).mockResolvedValue(huntFixture());
    mount();
    await screen.findByText(f0.title);
    expect(
      screen.getByText(
        /Promote a finding to investigate it\. Draft a detection from a confirmed true positive\./i,
      ),
    ).toBeInTheDocument();
  });

  it('does not render the line when the hunt completed with no findings', async () => {
    vi.mocked(getHunt).mockResolvedValue(huntFixture([]));
    mount();
    await screen.findByText(/No findings\. The hunt found nothing notable/i);
    expect(screen.queryByText(/Promote a finding to investigate it/i)).toBeNull();
  });
});


// A hunt started from a lead named the kind and not the lead, and its
// objective is a paragraph of generated prose that pushed the findings below
// the fold on every lead hunt.
describe('HuntDetail — a hunt started from a lead', () => {
  const LEAD_HUNT: HuntDetailData = {
    ...huntFixture([f0]),
    kind: 'lead',
    objective: '[lead 12] Investigate 10.1.2.3. The lead formed from a finding and off hours.',
  };

  const LEAD = {
    id: 12,
    status: 'hunting',
    formed_at: '2026-09-18T10:00:00Z',
    updated_at: null,
    entities: [['host', '10.1.2.3']],
    kinds: ['prior_no_baseline'],
    weight_at_formation: 1.3,
    weight_now: 1.28,
    scope_count: 1,
    hunt_id: HUNT_ID,
    shadow: false,
    single_signal: false,
    dismissed_reason: null,
    dismissed_note: null,
    dismissed_by: null,
    dismissed_at: null,
    investigation_id: null,
    dismiss_reasons: ['other'],
    observations: [
      {
        id: 1,
        kind: 'prior_no_baseline',
        spec_id: 'identity-4662-dcsync-nonmachine',
        summary: 'Directory replication requested by localuser, not a machine account',
        occurrences: 1,
        born_at: '2026-09-18T10:00:00Z',
        first_seen_at: '2026-09-18T10:00:00Z',
        source: 'catalog',
        shadow: false,
        weight_now: 1.0,
        birth_weight: 1.0,
        evidence: null,
      },
    ],
  };

  beforeEach(() => {
    vi.mocked(getAbout).mockReset().mockResolvedValue(about(false));
    vi.mocked(getHunt).mockReset().mockResolvedValue(LEAD_HUNT);
    vi.mocked(getHunts)
      .mockReset()
      .mockResolvedValue([
        { id: HUNT_ID, starter: 'lead', leadId: 12 } as never,
      ]);
    vi.mocked(getLead).mockReset().mockResolvedValue(LEAD as never);
  });

  it('names the lead at the top and links to it', async () => {
    mount();
    const chip = await screen.findByTestId('hunt-lead-chip');
    expect(chip.textContent).toBe('Lead 12');
    expect(chip.getAttribute('href')).toBe('/leads/12');
    expect(chip.getAttribute('title')).toBe(CHIP_LEAD);
  });

  // The status word and the disposition were the two loudest words on the
  // page, and neither said what it meant.
  it('states the status word and the disposition', async () => {
    mount();
    await screen.findByTestId('hunt-lead-chip');
    expect(screen.getByText('Complete').getAttribute('title')).toBe(STATUS_COMPLETE);
    expect(screen.getByTestId('hunt-disposition').getAttribute('title')).toBe(DISPOSITION);
  });

  it('reads the lead id from the detail route when it sends one', async () => {
    vi.mocked(getHunt).mockResolvedValue({ ...LEAD_HUNT, leadId: 12, starter: 'lead' });
    mount();
    await screen.findByTestId('hunt-lead-chip');
    expect(getHunts).not.toHaveBeenCalled();
    expect(getLead).toHaveBeenCalledWith(12);
  });

  it('shows the observations the lead is made of', async () => {
    mount();
    const panel = await screen.findByTestId('hunt-lead-timeline');
    expect(within(panel).getByText('Lead timeline · 1 observation')).toBeTruthy();
    expect(
      within(panel).getByText('Directory replication requested by localuser, not a machine account'),
    ).toBeTruthy();
  });

  // The dismissal is a decision on the record, and a reopen is the next one.
  // The lead page ended the entry with "Reopened." and the hunt page did not,
  // so one entry read two ways.
  it('names a reopen on the dismissal, as the lead page does', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      status: 'open',
      dismissed_reason: 'benign_repeat',
      dismissed_note: null,
      dismissed_by: 'alice',
      dismissed_at: '2026-09-18T12:00:00Z',
    } as never);
    mount();
    const panel = await screen.findByTestId('hunt-lead-timeline');
    expect(within(panel).getByTestId('lead-dismissal').textContent).toContain('Reopened.');
  });

  it('claims no reopen while the lead is still dismissed', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      status: 'dismissed',
      dismissed_reason: 'benign_repeat',
      dismissed_note: null,
      dismissed_by: 'alice',
      dismissed_at: '2026-09-18T12:00:00Z',
    } as never);
    mount();
    const panel = await screen.findByTestId('hunt-lead-timeline');
    expect(within(panel).getByTestId('lead-dismissal').textContent).not.toContain('Reopened.');
  });

  it('puts the raw objective behind a toggle', async () => {
    mount();
    const toggle = await screen.findByTestId('hunt-objective-toggle');
    expect(toggle.textContent).toBe('Show objective');
    expect(screen.queryByTestId('hunt-objective')).toBeNull();
    fireEvent.click(toggle);
    expect(screen.getByTestId('hunt-objective').textContent).toBe(LEAD_HUNT.objective);
    expect(screen.getByTestId('hunt-objective-toggle').textContent).toBe('Hide objective');
  });

  it('names no lead on a hunt an analyst typed', async () => {
    vi.mocked(getHunt).mockResolvedValue(huntFixture([f0]));
    mount();
    await screen.findByTestId('hunt-objective-toggle');
    expect(screen.queryByTestId('hunt-lead-chip')).toBeNull();
    expect(screen.queryByTestId('hunt-lead-timeline')).toBeNull();
    expect(getLead).not.toHaveBeenCalled();
  });
});
