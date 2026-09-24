// A promoted hunt finding (kind='hunt') has no Security Onion alert behind
// it — the anchor is telemetry, not a detector doc, and the backend refuses
// every SO write for it (Task 6). These tests pin the honest-UI half: every
// affordance that would end in a refused write is hidden or disabled, and
// the finding's provenance (which hunt, which objective) is always visible.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv, RecommendedAction } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
}));

import { Investigation } from './Investigation';

const ackAction: RecommendedAction = {
  id: 'act-1',
  title: 'Acknowledge the alert',
  tag: 'ack',
  rationale: 'The evidence supports a clean close-out.',
};

const baseInv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'Beaconing to rare external IP',
    kind: 'suricata',
    host: '192.0.2.10',
    ip: '198.51.100.7',
    verdict: 'true_positive',
    conf: 0.8,
    rationale: 'promoted finding',
    summary: [{ t: 'text', v: 'evidence' }],
    status: 'complete',
    elapsedLabel: '4m 5s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

describe('hunt-kind settled bar', () => {
  it('suppresses the settled bar for a promoted finding', () => {
    render(
      <MemoryRouter>
        <Investigation inv={baseInv({ kind: 'hunt', huntId: '01HUNT0000000000000000000000' })} layout="page" />
      </MemoryRouter>,
    );
    expect(screen.queryByText(/Verdict settled\. Take action\./i)).toBeNull();
  });

  it('keeps the settled bar for a suricata-kind run', () => {
    render(
      <MemoryRouter>
        <Investigation inv={baseInv({ kind: 'suricata' })} layout="page" />
      </MemoryRouter>,
    );
    expect(screen.getByText(/Verdict settled\. Take action\./i)).toBeTruthy();
  });
});

describe('hunt-kind provenance strip', () => {
  it('renders the objective and links to the hunt', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({
            kind: 'hunt',
            huntId: '01HUNTABC000000000000000000',
            huntObjective: 'Sweep for beaconing to rare external IPs',
          })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.getByText('Promoted from hunt')).toBeTruthy();
    const link = screen.getByRole('link', { name: 'Sweep for beaconing to rare external IPs' });
    expect(link).toHaveAttribute('href', '/hunts/01HUNTABC000000000000000000');
  });

  it('falls back to the hunt id as the link text when the hunt was deleted (huntObjective null)', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({ kind: 'hunt', huntId: '01HUNTDELETED0000000000000', huntObjective: null })}
          layout="page"
        />
      </MemoryRouter>,
    );
    const link = screen.getByRole('link', { name: '01HUNTDELETED0000000000000' });
    expect(link).toHaveAttribute('href', '/hunts/01HUNTDELETED0000000000000');
  });

  it('does not render the strip for a non-hunt investigation', () => {
    render(
      <MemoryRouter>
        <Investigation inv={baseInv({ kind: 'suricata' })} layout="page" />
      </MemoryRouter>,
    );
    expect(screen.queryByText('Promoted from hunt')).toBeNull();
  });
});

describe('hunt-kind toolbar gates', () => {
  it('hides Re-run and Deep re-run for a promoted finding', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({ kind: 'hunt', huntId: '01HUNT0000000000000000000000', meta: { model: 'x', ranBy: 'a', ranAt: 't', toolCalls: 0, pivots: 0 } })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.queryByRole('button', { name: /Re-run investigation/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /Deep re-run/i })).toBeNull();
  });

  it('keeps Re-run for a suricata-kind run', () => {
    render(
      <MemoryRouter>
        <Investigation inv={baseInv({ kind: 'suricata' })} layout="page" />
      </MemoryRouter>,
    );
    expect(screen.getByRole('button', { name: /Re-run investigation/i })).toBeTruthy();
  });

  it('hides Request more info for a promoted finding, even when the fixture otherwise qualifies', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({
            kind: 'hunt',
            huntId: '01HUNT0000000000000000000000',
            verdict: 'needs_more_info',
            openQuestions: ['Is this host normally this chatty at night?'],
            fallback: null,
          })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.queryByRole('button', { name: /Request more info/i })).toBeNull();
    // The rest of the open-questions block still renders — only the re-run
    // affordance is gated.
    expect(screen.getByText(/Is this host normally this chatty at night\?/i)).toBeTruthy();
  });

  it('shows Request more info for a suricata-kind run with open questions', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({
            verdict: 'needs_more_info',
            openQuestions: ['Is this host normally this chatty at night?'],
            fallback: null,
          })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.getByRole('button', { name: /Request more info/i })).toBeTruthy();
  });
});

describe('hunt-kind error-state re-run', () => {
  // An errored/interrupted/cancelled run is exactly when an analyst reaches
  // for Re-run — but the API refuses it (409 hunt_kind_no_rerun) once
  // promotion owns the anchor. failedEl points to the sanctioned path
  // instead of offering a dead-end button.
  it('replaces Re-run with a re-promote pointer to the hunt on a failed run', () => {
    const { container } = render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({
            kind: 'hunt',
            huntId: '01HUNTERR00000000000000000',
            huntObjective: 'Sweep for beaconing to rare external IPs',
            status: 'error',
          })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.queryByRole('button', { name: /Re-run investigation/i })).toBeNull();
    expect(container.textContent).toContain('Re-promote this finding from its hunt to re-run it.');
    // The prose right above that pointer must not ALSO instruct "re-run it" —
    // two different meanings ("click a button" vs "go re-promote from the
    // hunt") stacked at the same spot is the bug under test here.
    expect(container.textContent).toContain(
      'The run may have stalled. The agent may have crashed. Re-promote it from its hunt to try again.',
    );
    expect(container.textContent).not.toContain('The agent may have crashed. Re-run it to try again.');
    const link = screen.getByRole('link', { name: 'Sweep for beaconing to rare external IPs' });
    expect(link).toHaveAttribute('href', '/hunts/01HUNTERR00000000000000000');
  });

  it('keeps the Re-run button on a failed suricata-kind run', () => {
    const { container } = render(
      <MemoryRouter>
        <Investigation inv={baseInv({ kind: 'suricata', status: 'error' })} layout="page" />
      </MemoryRouter>,
    );
    // Two: the toolbar's own Re-run plus failedEl's — both are ordinary for
    // a suricata-kind run; only the count (not zero) is under test here.
    expect(screen.getAllByRole('button', { name: /Re-run investigation/i }).length).toBeGreaterThan(0);
    expect(container.textContent).not.toContain('Re-promote this finding');
    // Suricata prose is byte-identical to before this polish pass.
    expect(container.textContent).toContain(
      'The run may have stalled. The agent may have crashed. Re-run it to try again.',
    );
  });
});

describe('hunt-kind pipeline-fallback re-run', () => {
  // Task 9's fallback panel offers the same startHunt('reRun') path as
  // failedEl — must gate identically, and must NOT gate the Dismiss button
  // beside it (dismissing a pipeline error is a soc-ai-only write, not SO).
  it('replaces Re-run with a re-promote pointer in the fallback panel, keeps Dismiss', () => {
    const { container } = render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({
            kind: 'hunt',
            huntId: '01HUNTFB000000000000000000',
            status: 'complete',
            fallback: { provenance: 'pipeline_fallback' },
          })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.queryByRole('button', { name: /Re-run investigation/i })).toBeNull();
    expect(container.textContent).toContain('Re-promote this finding from its hunt to re-run it.');
    // Same copy-tension fix as failedEl: the sentence above the pointer must
    // agree with it instead of also saying "re-run it".
    expect(container.textContent).toContain(
      'soc·ai recorded it as needs_more_info as a placeholder. Re-promote it from its hunt to try again.',
    );
    expect(container.textContent).not.toContain('placeholder. Re-run it to get a real verdict.');
    // Two identical links here by design: the fallback panel's own pointer AND
    // the always-present provenance strip both target the same hunt — assert
    // on the href existing rather than a single unique match.
    expect(container.querySelectorAll('a[href="/hunts/01HUNTFB000000000000000000"]').length).toBeGreaterThan(
      0,
    );
    expect(screen.getByRole('button', { name: /Dismiss/i })).toBeTruthy();
  });

  it('keeps the Re-run button in the fallback panel for a suricata-kind run', () => {
    const { container } = render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({
            kind: 'suricata',
            status: 'complete',
            fallback: { provenance: 'pipeline_fallback' },
          })}
          layout="page"
        />
      </MemoryRouter>,
    );
    // Two: the toolbar's own Re-run plus the fallback panel's — both are
    // ordinary for a suricata-kind run; only the count (not zero) is under
    // test here.
    expect(screen.getAllByRole('button', { name: /Re-run investigation/i }).length).toBeGreaterThan(0);
    // Suricata prose is byte-identical to before this polish pass.
    expect(container.textContent).toContain(
      'soc·ai recorded it as needs_more_info as a placeholder. Re-run it to get a real verdict.',
    );
  });
});

describe('hunt-kind inconclusive/needs_more_info wayfinding', () => {
  // F13 (1.3 dogfood): a complete hunt-kind run that lands inconclusive (or
  // needs_more_info) has every re-run affordance hidden — Re-run, Deep
  // re-run, Request more info all gate on kind!=='hunt' — yet the
  // inconclusive copy said "dig deeper with a focused re-investigation".
  // That names a path that does not exist on this screen. The hunt-kind copy
  // now says what actually refines a promoted finding.
  it('replaces the focused-re-investigation copy with re-promote wayfinding on an inconclusive promoted finding', () => {
    const { container } = render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({
            kind: 'hunt',
            huntId: '01HUNTINC00000000000000000',
            huntObjective: 'Sweep for beaconing to rare external IPs',
            verdict: 'inconclusive',
            fallback: null,
          })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(container.textContent).toContain(
      'Re-promote this finding from its hunt to refine it. You can also ask a follow-up below. This screen cannot re-run a promoted finding.',
    );
    expect(container.textContent).not.toContain('focused re-investigation');
    // No re-run affordance anywhere on this shape — the copy and the buttons
    // must agree.
    expect(screen.queryByRole('button', { name: /Re-run investigation/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /Request more info/i })).toBeNull();
  });

  it('keeps the focused-re-investigation copy for a suricata-kind inconclusive run', () => {
    const { container } = render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({ kind: 'suricata', verdict: 'inconclusive', fallback: null })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(container.textContent).toContain(
      'The model could not converge on a verdict. Start a focused re-investigation. You can also resolve it in chat.',
    );
    expect(container.textContent).not.toContain('This screen cannot re-run a promoted finding');
  });

  it('adds the wayfinding line beside the open questions on a hunt-kind needs_more_info run', () => {
    const { container } = render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({
            kind: 'hunt',
            huntId: '01HUNTNMI00000000000000000',
            verdict: 'needs_more_info',
            openQuestions: ['Is this host normally this chatty at night?'],
            fallback: null,
          })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.getByText(/Is this host normally this chatty at night\?/i)).toBeTruthy();
    expect(container.textContent).toContain(
      'Re-promote this finding from its hunt to refine it. You can also ask a follow-up below. This screen cannot re-run a promoted finding.',
    );
    expect(screen.queryByRole('button', { name: /Request more info/i })).toBeNull();
  });
});

describe('hunt-kind recommended actions', () => {
  it('disables the Approve/Execute button with the explanatory title, but leaves Reject clickable (local-only, not an SO write)', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({ kind: 'hunt', huntId: '01HUNT0000000000000000000000', actions: [ackAction] })}
          layout="page"
        />
      </MemoryRouter>,
    );
    const approve = screen.getByRole('button', { name: /Approve|Execute/i });
    expect(approve).toBeDisabled();
    expect(approve).toHaveAttribute('title', 'A promoted finding has no Security Onion alert to act on');
    const reject = screen.getByRole('button', { name: /Reject|Dismiss/i });
    expect(reject).not.toBeDisabled();
  });

  it('leaves action buttons enabled for a suricata-kind run', () => {
    render(
      <MemoryRouter>
        <Investigation inv={baseInv({ kind: 'suricata', actions: [ackAction] })} layout="page" />
      </MemoryRouter>,
    );
    const approve = screen.getByRole('button', { name: /Approve|Execute/i });
    expect(approve).not.toBeDisabled();
  });

  it('does not fire onApprove when clicking a disabled action button', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({ kind: 'hunt', huntId: '01HUNT0000000000000000000000', actions: [ackAction] })}
          layout="page"
        />
      </MemoryRouter>,
    );
    const approve = screen.getByRole('button', { name: /Approve|Execute/i });
    fireEvent.click(approve);
    // Still disabled, no "Writing to Security Onion…" transition.
    expect(screen.queryByText(/Writing to Security Onion/i)).toBeNull();
  });
});
