import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import type { CampaignLadderStep } from '../../lib/api';
import { STAGE_COLOR } from '../../lib/campaignViz';
import { CAMPAIGN } from '../../test/campaign';
import { StageLadder } from './StageLadder';

function mount(ladder: CampaignLadderStep[] = CAMPAIGN.ladder) {
  return render(
    <MemoryRouter>
      <StageLadder ladder={ladder} />
    </MemoryRouter>,
  );
}

describe('StageLadder', () => {
  it('draws five steps in the order of the stages', () => {
    mount();
    const steps = within(screen.getByTestId('stage-ladder')).getAllByRole('listitem');
    expect(steps.map((s) => s.getAttribute('data-testid'))).toEqual([
      'ladder-reconnaissance',
      'ladder-attempt',
      'ladder-access',
      'ladder-action',
      'ladder-movement',
    ]);
  });

  it('states the headline, the time, the evidence and the link of a reached step, in that order', () => {
    mount();
    const action = screen.getByTestId('ladder-action');
    expect(action).toHaveAttribute('data-reached', 'true');
    const headline = within(action).getByTestId('ladder-headline');
    expect(headline).toHaveTextContent('actor-a executed a command on web-1 through a web shell.');
    expect(headline.className).toContain('text-text-2');
    expect(headline.className).toContain('break-words');
    const evidence = within(action).getByTestId('ladder-evidence');
    expect(evidence).toHaveTextContent(CAMPAIGN.ladder[3].evidence!.label);
    // The label of the record wraps. It is never cut.
    expect(evidence.className).toContain('break-words');
    expect(evidence.className).toContain('font-mono');
    const link = within(action).getByRole('link', { name: 'View the evidence' });
    expect(link).toHaveAttribute('href', '/investigation/run-shell');
    // The order: the stage name, the headline, the time, the evidence, the link.
    const text = action.textContent ?? '';
    const at = (part: string) => text.indexOf(part);
    expect(at('Action on the target')).toBeLessThan(at('actor-a executed'));
    expect(at('actor-a executed')).toBeLessThan(at('2026-10-28 22:44:56 UTC'));
    expect(at('2026-10-28 22:44:56 UTC')).toBeLessThan(at('suricata.alert'));
    expect(at('suricata.alert')).toBeLessThan(at('View the evidence'));
    // The number of a reached step wears the color of its stage.
    const number = action.querySelector('span[aria-hidden]') as HTMLElement;
    expect(number).toHaveTextContent('4');
    expect(number.style.background).toBe(STAGE_COLOR.action);
    // NEGATIVE CONTROL: a reached stage does not read "Not seen", and it states no count.
    expect(within(action).queryByText('Not seen')).toBeNull();
    expect(action).not.toHaveTextContent(/\b1 (member|run|investigation)/);
  });

  it('states the evidence alone with no headline, and the time and the link with neither', () => {
    const [recon, attempt] = CAMPAIGN.ladder;
    mount([{ ...attempt, headline: null }, { ...recon, headline: undefined, evidence: undefined }]);
    const step = screen.getByTestId('ladder-attempt');
    expect(within(step).queryByTestId('ladder-headline')).toBeNull();
    expect(within(step).getByTestId('ladder-evidence')).toHaveTextContent(
      'ET EXPLOIT PHP file upload, 192.0.2.10 to 192.0.2.20',
    );
    // A server of an earlier release sends neither.
    const bare = screen.getByTestId('ladder-reconnaissance');
    expect(within(bare).queryByTestId('ladder-headline')).toBeNull();
    expect(within(bare).queryByTestId('ladder-evidence')).toBeNull();
    expect(bare).toHaveTextContent('2026-10-24 00:40:00 UTC');
    expect(within(bare).getByRole('link', { name: 'View the evidence' })).toHaveAttribute(
      'href',
      '/investigation/run-actor',
    );
  });

  it('reads "Not seen" for a step that the campaign did not reach', () => {
    mount();
    const movement = screen.getByTestId('ladder-movement');
    expect(movement).toHaveAttribute('data-reached', 'false');
    expect(within(movement).getByText('Not seen').className).toContain('text-faint');
    expect(within(movement).queryByRole('link')).toBeNull();
    // NEGATIVE CONTROL: the number of a step not seen wears no stage color.
    expect((movement.querySelector('span[aria-hidden]') as HTMLElement).style.background).toBe('');
  });

  it('states the earlier time with "by" when a later stage proves a stage earlier', () => {
    // Access has its first proof on 2026-11-12. The action on the target has
    // proof on 2026-10-28, and an action needs access.
    const ladder = CAMPAIGN.ladder.map((s) =>
      s.stage === 'access'
        ? {
            ...s,
            reached: true,
            firstAt: '2026-11-12T00:09:00Z',
            members: 1,
            proofRunId: 'inv-late',
            heldBy: { at: '2026-10-28T22:44:56Z', stage: 'action' as const },
          }
        : s,
    );
    mount(ladder);
    const access = screen.getByTestId('ladder-access');
    expect(access).toHaveAttribute('data-reached', 'true');
    expect(access).toHaveAttribute('data-implied', 'false');
    expect(within(access).getByTestId('ladder-time')).toHaveTextContent(/^by 2026-10-28 22:44:56/);
    const note = within(access).getByTestId('ladder-held');
    expect(note).toHaveTextContent('Action on the target needs this stage and has proof at this time.');
    expect(note).toHaveTextContent(/First proof of this stage itself: 2026-11-12 00:09:00/);
    expect(note.className).toContain('break-words');
    // The times of the ladder do not run backward.
    const times = ['attempt', 'access', 'action'].map(
      (stage) => within(screen.getByTestId(`ladder-${stage}`)).getByTestId('ladder-time').textContent ?? '',
    );
    const stamps = times.map((t) => t.replace(/^by /, ''));
    expect([...stamps].sort()).toEqual(stamps);
    // NEGATIVE CONTROL: a stage with the earliest proof of its own states no "by".
    expect(within(screen.getByTestId('ladder-action')).getByTestId('ladder-time').textContent).not.toMatch(/^by /);
    expect(within(screen.getByTestId('ladder-action')).queryByTestId('ladder-held')).toBeNull();
  });

  it('marks a stage that a later stage needs and that no investigation proves', () => {
    const ladder = CAMPAIGN.ladder.map((s) =>
      s.stage === 'access' ? { ...s, heldBy: { at: '2026-10-28T22:44:56Z', stage: 'action' as const } } : s,
    );
    mount(ladder);
    const access = screen.getByTestId('ladder-access');
    expect(access).toHaveAttribute('data-reached', 'false');
    expect(access).toHaveAttribute('data-implied', 'true');
    expect(within(access).queryByText('Not seen')).toBeNull();
    expect(within(access).getByTestId('ladder-time')).toHaveTextContent(/^by 2026-10-28 22:44:56/);
    expect(within(access).getByTestId('ladder-held')).toHaveTextContent(
      'No investigation proves this stage itself. Action on the target needs this stage and has proof at this time.',
    );
    // A ring in the color of the stage, and no filled dot: the stage has no proof of its own.
    const dot = access.querySelector('span[aria-hidden]') as HTMLElement;
    expect(dot.style.background).toBe('');
    expect(dot.style.borderColor).not.toBe('');
    expect(within(access).queryByRole('link')).toBeNull();
    // NEGATIVE CONTROL: a stage that no later stage needs still reads "Not seen".
    expect(within(screen.getByTestId('ladder-movement')).getByText('Not seen')).toBeInTheDocument();
    expect(screen.getByTestId('ladder-movement')).toHaveAttribute('data-implied', 'false');
  });

  it('draws five steps when the server sends fewer', () => {
    mount([CAMPAIGN.ladder[1]]);
    const ladder = screen.getByTestId('stage-ladder');
    expect(within(ladder).getAllByRole('listitem')).toHaveLength(5);
    expect(within(ladder).getAllByText('Not seen')).toHaveLength(4);
  });
});
