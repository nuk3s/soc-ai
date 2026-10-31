// Re-run on the investigation of a hunt finding (2026-10-30).
//
// The page of a finding run hid Re-run. The API refused Request more info and
// POST /hunt for the run (409 hunt_kind_no_rerun), and the hunt page returned
// the finished run on each press. A finished needs_more_info run of a finding
// could never run again. Re-run now posts the promote route with rerun true,
// and the page hands the new id on the way the alert Re-run does.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv, PromotedFinding } from '../lib/types';

const promoteFinding = vi.fn();
const startHunt = vi.fn();
const requestMoreInfo = vi.fn();

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
  getActionScope: vi.fn().mockResolvedValue(null),
  promoteFinding: (...args: unknown[]) => promoteFinding(...args),
  startHunt: (...args: unknown[]) => startHunt(...args),
  requestMoreInfo: (...args: unknown[]) => requestMoreInfo(...args),
}));

import { ApiError } from '../lib/api';
import {
  FINDING_RUN_STILL_RUNS,
  Investigation,
  SUPERSEDED_LOCK,
  newRunConfirmText,
  supersededSentence,
} from './Investigation';

const HUNT = '01HUNTRERUN000000000000000';

const finding: PromotedFinding = {
  ordinal: 1,
  label: 'F2',
  title: 'Beacon from a web server',
  hosts: ['192.0.2.10'],
  attacker: '198.51.100.7',
  victim: '192.0.2.10',
  huntId: HUNT,
  huntTitle: 'Hunt for beacons',
};

const findingRun = (over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-F2',
    groupId: 'tel-doc-00000001',
    name: 'Beacon from a web server',
    kind: 'hunt',
    host: '192.0.2.10',
    ip: '198.51.100.7',
    verdict: 'needs_more_info',
    conf: 0.5,
    rationale: 'The run needs the DNS answers of the beacon.',
    summary: [{ t: 'text', v: 'x' }],
    status: 'complete',
    elapsedLabel: '3m',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    huntId: HUNT,
    huntObjective: 'Hunt for beacons',
    promotedFinding: finding,
    openQuestions: ['Which domain did 192.0.2.10 resolve before each call?'],
    fallback: null,
    meta: { model: 'm', ranBy: 'system:hunt', ranAt: 't', toolCalls: 0, pivots: 0 },
    ...over,
  }) as Inv;

const analystResolution = {
  original_verdict: 'needs_more_info',
  resolved_via: 'manual' as const,
  resolved_by: 'alice',
  resolved_at: '2026-10-30T09:00:00Z',
};

const mount = (i: Inv, onReHunt = vi.fn()) =>
  render(
    <MemoryRouter>
      <Investigation inv={i} layout="page" onReHunt={onReHunt} />
    </MemoryRouter>,
  );

const toolbar = () => screen.getByTestId('verdict-toolbar');
const toolbarReRun = () => within(toolbar()).getByRole('button', { name: 'Re-run investigation' });

beforeEach(() => {
  promoteFinding.mockReset();
  promoteFinding.mockResolvedValue({ investigation_id: 'INV-NEW' });
  startHunt.mockReset();
  requestMoreInfo.mockReset();
});

describe('Re-run on a finding run', () => {
  it('shows Re-run on a finished finding run, without Deep re-run or Request more info', () => {
    mount(findingRun());
    expect(toolbarReRun()).not.toBeDisabled();
    // The run made no tool call. An alert run offers Deep re-run then. The
    // promote route has no deep variant, so a finding run does not.
    expect(screen.queryByRole('button', { name: /Deep re-run/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /Request more info/i })).toBeNull();
  });

  it('hides Re-run while the run is running', () => {
    mount(findingRun({ status: 'investigating', verdict: 'untriaged' }));
    expect(screen.queryByRole('button', { name: /Re-run investigation/i })).toBeNull();
  });

  it('starts the new run through the promote route with rerun true', async () => {
    const onReHunt = vi.fn();
    mount(findingRun(), onReHunt);
    fireEvent.click(toolbarReRun());
    await waitFor(() => expect(onReHunt).toHaveBeenCalledWith('INV-NEW'));
    expect(promoteFinding).toHaveBeenCalledTimes(1);
    expect(promoteFinding).toHaveBeenCalledWith(HUNT, 1, { rerun: true });
    // The alert path refuses a finding run. It is never called.
    expect(startHunt).not.toHaveBeenCalled();
    expect(requestMoreInfo).not.toHaveBeenCalled();
  });

  it('hands on the run the server returns when a run of the finding already runs', async () => {
    promoteFinding.mockResolvedValue({ investigation_id: 'INV-RUNNING', existing: true });
    const onReHunt = vi.fn();
    mount(findingRun(), onReHunt);
    fireEvent.click(toolbarReRun());
    await waitFor(() => expect(onReHunt).toHaveBeenCalledWith('INV-RUNNING'));
  });

  it('asks first when an analyst set the verdict of the run, and names the finding', async () => {
    const onReHunt = vi.fn();
    mount(
      findingRun({
        verdict: 'false_positive',
        resolution: analystResolution,
      }),
      onReHunt,
    );
    fireEvent.click(toolbarReRun());
    const dialog = await screen.findByRole('dialog');
    expect(promoteFinding).not.toHaveBeenCalled();
    expect(dialog.textContent).toContain('alice set the verdict of this finding to false positive.');
    expect(dialog.textContent).toContain(
      'The verdict of the new run then replaces the analyst verdict on the hunt page.',
    );
    // The body and the buttons say one thing: the hunt page loses the
    // analyst verdict, and this run keeps it as a record.
    expect(dialog.textContent).not.toContain('keeps the analyst verdict');
    expect(dialog.textContent).not.toContain('this alert');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Replace the analyst verdict' }));
    await waitFor(() => expect(promoteFinding).toHaveBeenCalledWith(HUNT, 1, { rerun: true }));
    await waitFor(() => expect(onReHunt).toHaveBeenCalledWith('INV-NEW'));
  });

  it('keeps the analyst verdict when the analyst keeps it', async () => {
    mount(
      findingRun({
        verdict: 'false_positive',
        resolution: analystResolution,
      }),
    );
    fireEvent.click(toolbarReRun());
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Keep the analyst verdict' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(promoteFinding).not.toHaveBeenCalled();
  });

  it('states a refusal of the API beside the button', async () => {
    promoteFinding.mockRejectedValue(
      new ApiError('The hunt is still running. Open an investigation after the hunt lands its report.', 409, 'still_running'),
    );
    mount(findingRun());
    fireEvent.click(toolbarReRun());
    const strip = await screen.findByRole('alert');
    expect(strip.textContent).toContain('The API refused Re-run investigation.');
    expect(strip.textContent).toContain('The hunt is still running.');
  });

  it('names the finding when the API gives no answer', async () => {
    promoteFinding.mockRejectedValue(new Error('Request timed out.'));
    mount(findingRun());
    fireEvent.click(toolbarReRun());
    const strip = await screen.findByRole('alert');
    expect(strip.textContent).toContain('The API gave no answer to Re-run investigation.');
    expect(strip.textContent).toContain('a newer run of this finding');
  });

  it('says Re-run in the open-questions block of a finding run', () => {
    const { container } = mount(findingRun());
    expect(container.textContent).toContain(
      'Re-run the investigation of this finding to refine it. You can also ask a follow-up in Ask soc-ai.',
    );
    expect(container.textContent).not.toContain('This screen cannot re-run the investigation of a finding');
  });

  it('offers Re-run in the failure panel of a failed finding run', async () => {
    const onReHunt = vi.fn();
    const { container } = mount(
      findingRun({ status: 'error', verdict: 'untriaged', openQuestions: [] }),
      onReHunt,
    );
    expect(container.textContent).toContain('soc-ai recorded no cause. Re-run it to try again.');
    expect(container.textContent).not.toContain('Open an investigation on it again from its hunt.');
    const buttons = screen.getAllByRole('button', { name: 'Re-run investigation' });
    expect(buttons.length).toBe(2);
    fireEvent.click(buttons[1]);
    await waitFor(() => expect(promoteFinding).toHaveBeenCalledWith(HUNT, 1, { rerun: true }));
    await waitFor(() => expect(onReHunt).toHaveBeenCalledWith('INV-NEW'));
  });

  it('offers Re-run in the pipeline-error panel of a finding run', () => {
    const { container } = mount(
      findingRun({ fallback: { provenance: 'pipeline_fallback' } }),
    );
    expect(container.textContent).toContain(
      'soc-ai recorded the verdict Needs more info as a placeholder. Re-run it to get a real verdict.',
    );
    expect(screen.getAllByRole('button', { name: 'Re-run investigation' }).length).toBe(2);
    expect(screen.getByRole('button', { name: /Dismiss/i })).toBeTruthy();
  });

  it('offers no Re-run when the hunt of the finding is gone', () => {
    // The promote route answers 404 for a deleted hunt. The page names the
    // finding from the stored subject, and keeps the button off.
    mount(findingRun({ huntObjective: null }));
    expect(screen.queryByRole('button', { name: /Re-run investigation/i })).toBeNull();
  });
});

describe('newRunConfirmText for a finding', () => {
  it('names the finding and the hunt page', () => {
    const lines = newRunConfirmText(
      'rerun',
      { analyst: { verdict: 'true_positive', by: 'alice', otherRun: false }, replay: false, live: null },
      'finding',
    );
    expect(lines).toEqual([
      'alice set the verdict of this finding to true positive.',
      'A re-run starts a new run of the finding. The verdict of the new run then replaces the analyst verdict on the hunt page.',
      'The run with the analyst verdict stays as a record.',
    ]);
  });

  it('keeps the alert words by default', () => {
    const lines = newRunConfirmText('rerun', {
      analyst: { verdict: 'true_positive', by: 'alice', otherRun: false },
      replay: false,
      live: null,
    });
    expect(lines?.[0]).toBe('alice set the verdict of this alert to true positive.');
  });
});

describe('an older run of a finding', () => {
  // A Re-run leaves the old run as a record. The server names the newer run
  // of the finding in supersededBy, and the page locks the old one.
  const replaced: Partial<Inv> = {
    supersededBy: 'INV-NEWER',
    supersededRun: { id: 'INV-NEWER', status: 'complete', verdict: 'true_positive', conf: 0.9 },
  };

  it('locks Re-run and Override, and names the newer run of the finding', () => {
    mount(findingRun(replaced));
    expect(screen.getByTestId('superseded-banner').textContent).toContain(
      'A newer run on this finding reached true positive (0.90).',
    );
    const reRun = toolbarReRun();
    expect(reRun).toBeDisabled();
    expect(reRun).toHaveAttribute('title', SUPERSEDED_LOCK);
    expect(within(toolbar()).getByRole('button', { name: /Override verdict/i })).toBeDisabled();
    // The Re-run of the open-questions block is off too.
    for (const button of screen.getAllByRole('button', { name: 'Re-run investigation' })) {
      expect(button).toBeDisabled();
    }
    fireEvent.click(reRun);
    expect(promoteFinding).not.toHaveBeenCalled();
  });

  it('NEGATIVE CONTROL: the sentence of an alert run keeps the alert words', () => {
    expect(supersededSentence({ id: 'x', status: 'running' })).toBe(
      'A newer run on this alert is in progress.',
    );
    expect(supersededSentence({ id: 'x', status: 'running' }, 'finding')).toBe(
      'A newer run on this finding is in progress.',
    );
  });
});

describe('Re-run on a stuck finding run', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  const mountStuck = (onReHunt = vi.fn()) => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const view = mount(findingRun({ status: 'investigating', verdict: 'untriaged' }), onReHunt);
    // Five minutes with no new step: the page calls the run stuck.
    act(() => {
      vi.advanceTimersByTime(5 * 60_000 + 1);
    });
    vi.useRealTimers();
    return view;
  };

  it('states that the run still runs when the server returns this run', async () => {
    // The server row still reads running, so the promote route returns this
    // same run. A hand-off to the same id changed nothing on the page.
    promoteFinding.mockResolvedValue({ investigation_id: 'INV-F2', existing: true });
    const onReHunt = vi.fn();
    mountStuck(onReHunt);
    expect(screen.getByText('This investigation seems stuck')).toBeTruthy();
    fireEvent.click(toolbarReRun());
    const strip = await screen.findByRole('alert');
    expect(strip.textContent).toContain(FINDING_RUN_STILL_RUNS);
    expect(promoteFinding).toHaveBeenCalledWith(HUNT, 1, { rerun: true });
    expect(onReHunt).not.toHaveBeenCalled();
  });

  it('NEGATIVE CONTROL: hands on another running run of the finding', async () => {
    promoteFinding.mockResolvedValue({ investigation_id: 'INV-OTHER', existing: true });
    const onReHunt = vi.fn();
    mountStuck(onReHunt);
    fireEvent.click(toolbarReRun());
    await waitFor(() => expect(onReHunt).toHaveBeenCalledWith('INV-OTHER'));
    expect(screen.queryByText(FINDING_RUN_STILL_RUNS, { exact: false })).toBeNull();
  });
});
