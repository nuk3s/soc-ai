// Dogfood 2026-10-06 W4: the hunt page of a lead hunt offered Re-hunt and
// Delete, and the analyst went back to the lead to decide on it. Delete sat
// beside Re-hunt at the same weight on every hunt page.
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
  getHunts: vi.fn().mockResolvedValue([]),
  getLead: vi.fn(),
  promoteLead: vi.fn(),
  dismissLead: vi.fn(),
  deleteHunt: vi.fn(),
  getHuntChat: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  postHuntChat: vi.fn(),
  getAbout: vi.fn(),
}));

import { deleteHunt, dismissLead, getAbout, getHunt, getLead, promoteLead } from '../lib/api';
import { HuntDetail } from './HuntDetail';

const about: AboutInfo = {
  version: '1.0.0',
  repo_url: 'https://example.test/soc-ai',
  license: 'MIT',
  update_check_enabled: false,
  general_chat_enabled: true,
  sigma_authoring_enabled: false,
};

function hunt(over: Partial<HuntDetailData> = {}): HuntDetailData {
  return {
    id: 'H-6',
    objective: '[lead 6] Investigate domainadmin, 10.1.10.11. The lead formed.',
    kind: 'lead',
    status: 'complete',
    narrative: 'The two events are attribute writes.',
    findings: [],
    affectedHosts: [],
    mitreTechniques: [],
    recommendedActions: [],
    confidence: 0.6,
    startedBy: 'analyst',
    elapsedLabel: '6m 0s',
    elapsedSec: 360,
    ts: '2026-10-06T00:00:00Z',
    timeline: [],
    diff: null,
    leadId: 6,
    outcome: 'no_threat',
    outcome_label: 'No threat found',
    ...over,
  };
}

function lead(status: string) {
  return {
    id: 6,
    status,
    formed_at: '2026-10-06T00:00:00Z',
    updated_at: '2026-10-06T00:00:00Z',
    entities: [['user', 'domainadmin']],
    kinds: ['catalog_match'],
    weight: 1,
    hunt_id: 'H-6',
    weight_now: 1,
    single_signal: true,
    dismissed_reason: null,
    dismissed_note: null,
    dismissed_by: null,
    dismissed_at: null,
    investigation_id: null,
    dismiss_reasons: ['expected_for_role', 'other'],
    observations: [],
  } as unknown as Awaited<ReturnType<typeof getLead>>;
}

function mount() {
  return render(
    <MemoryRouter initialEntries={['/hunts/H-6']}>
      <Routes>
        <Route path="/hunts/:id" element={<HuntDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('HuntDetail lead decision', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about);
  });

  // The hunt investigates what it finds, so the bar offers no investigation
  // of the lead (owner, 2026-10-07). The manual "Open an investigation" sits
  // on a finding with no investigation.
  it('shows "Lead 6 waits on you" with "Dismiss lead" and no investigation control', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt());
    vi.mocked(getLead).mockResolvedValue(lead('hunting'));
    mount();
    const bar = await screen.findByTestId('hunt-lead-decision');
    expect(bar.textContent).toContain('Lead 6 waits on you.');
    expect(within(bar).getByRole('button', { name: 'Dismiss lead' })).toBeTruthy();
    expect(within(bar).queryByRole('button', { name: /Open an investigation|Promote/ })).toBeNull();
    expect(screen.queryByTestId('hunt-lead-promote')).toBeNull();
    expect(promoteLead).not.toHaveBeenCalled();
    expect(navigate).not.toHaveBeenCalled();
  });

  it('dismisses through the lead route with a reason', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt());
    vi.mocked(getLead).mockResolvedValue(lead('open'));
    vi.mocked(dismissLead).mockResolvedValue(lead('dismissed'));
    mount();
    fireEvent.click(await screen.findByTestId('hunt-lead-dismiss'));
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'expected_for_role' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm dismiss' }));
    await waitFor(() =>
      expect(dismissLead).toHaveBeenCalledWith(6, 'expected_for_role', undefined),
    );
  });

  // R3-I4: the analyst dismissed a lead whose hunt had a confirmed threat,
  // and nothing on the form said so.
  it('names the open threat finding on the Dismiss form', async () => {
    const finding = (title: string, verdict: string) => ({
      title,
      detail: 'd',
      severity: 'high',
      category: 'threat',
      hosts: ['192.0.2.11'],
      citations: [],
      investigationId: `inv-${verdict}`,
      investigationStatus: 'complete' as const,
      verdict,
    });
    vi.mocked(getHunt).mockResolvedValue(
      hunt({
        findings: [
          finding('RC4 service ticket for svc_sql', 'true_positive'),
          finding('A cleared scan', 'false_positive'),
        ],
      }),
    );
    vi.mocked(getLead).mockResolvedValue(lead('hunting'));
    mount();
    fireEvent.click(await screen.findByTestId('hunt-lead-dismiss'));
    expect(screen.getByTestId('dismiss-threat-warning').textContent).toBe(
      'The hunt of this lead found a threat: RC4 service ticket for svc_sql. Dismiss closes the ' +
        'lead. The threat finding stays open on the hunt. ',
    );
    // Escape closes the form (R3-D14).
    fireEvent.keyDown(screen.getByLabelText('Reason'), { key: 'Escape' });
    await waitFor(() => expect(screen.queryByLabelText('Reason')).toBeNull());
  });

  it('shows no bar on a closed lead or a running hunt', async () => {
    // Negative controls: a dismissed lead waits on no one, and a running hunt
    // has nothing to decide yet.
    vi.mocked(getHunt).mockResolvedValue(hunt());
    vi.mocked(getLead).mockResolvedValue(lead('dismissed'));
    const { unmount } = mount();
    await screen.findByTestId('hunt-title');
    await waitFor(() => expect(getLead).toHaveBeenCalled());
    expect(screen.queryByTestId('hunt-lead-decision')).toBeNull();
    unmount();

    vi.mocked(getHunt).mockResolvedValue(hunt({ status: 'running', outcome: 'running' }));
    vi.mocked(getLead).mockResolvedValue(lead('hunting'));
    mount();
    await screen.findByTestId('hunt-title');
    await waitFor(() => expect(getLead).toHaveBeenCalledTimes(2));
    expect(screen.queryByTestId('hunt-lead-decision')).toBeNull();
  });

  it('keeps Delete behind the overflow menu', async () => {
    vi.mocked(getHunt).mockResolvedValue(hunt({ leadId: null, kind: 'chat', objective: 'x' }));
    vi.mocked(deleteHunt).mockResolvedValue({ ok: true } as never);
    mount();
    await screen.findByTestId('hunt-title');
    expect(screen.queryByRole('button', { name: /^Delete/ })).toBeNull();
    fireEvent.click(screen.getByTestId('hunt-more'));
    fireEvent.click(screen.getByRole('menuitem', { name: /Delete hunt/ }));
    fireEvent.click(screen.getByRole('button', { name: /Confirm delete/ }));
    await waitFor(() => expect(deleteHunt).toHaveBeenCalledWith('H-6'));
  });
});
