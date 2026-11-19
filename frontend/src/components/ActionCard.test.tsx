// The recommended action card (dogfood 2026-10-06). An ack states its scope
// before the click, every write and every dismissal asks for a confirm, a
// dismissal shows who and when with an undo. The negative controls: the
// first click never writes, and Cancel writes nothing.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { RecommendedAction } from '../lib/types';

const getActionScope = vi.fn();
vi.mock('../lib/api', () => ({
  getActionScope: (...a: unknown[]) => getActionScope(...a),
}));

import { ActionCard, clockTime, confirmLabel } from './ActionCard';

const ack: RecommendedAction = { id: 'a0', title: 'Acknowledge alert', tag: 'ack', rationale: 'Benign.' };
const esc: RecommendedAction = { id: 'a1', title: 'Escalate to case', tag: 'escalate', rationale: 'Bad.' };

const GROUP_SCOPE = {
  tool: 'ack_alert',
  scope: 'group',
  count: 9,
  hosts: 2,
  held: 0,
  rangeLabel: 'the last 7 days',
  sentence: 'Acknowledge 9 alerts of this rule from the last 7 days, on 2 hosts.',
};

function mount(action: RecommendedAction, over: Partial<Parameters<typeof ActionCard>[0]> = {}) {
  const props = {
    action,
    index: 0,
    invId: 'INV-1',
    onExecute: vi.fn(),
    onDismiss: vi.fn(),
    onUndoDismiss: vi.fn(),
    ...over,
  };
  render(<ActionCard {...props} />);
  return props;
}

describe('ActionCard', () => {
  it('states the ack scope before the click and confirms before it writes', async () => {
    getActionScope.mockResolvedValueOnce(GROUP_SCOPE);
    const p = mount(ack);
    await waitFor(() =>
      expect(screen.getByTestId('action-scope').textContent).toBe(GROUP_SCOPE.sentence),
    );
    fireEvent.click(screen.getByRole('button', { name: /^Acknowledge$/ }));
    // Negative control: the first click opens the confirm and writes nothing.
    expect(p.onExecute).not.toHaveBeenCalled();
    const confirm = screen.getByTestId('action-confirm');
    expect(confirm.textContent).toContain('This writes to Security Onion.');
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge 9 alerts' }));
    expect(p.onExecute).toHaveBeenCalledWith('group');
  });

  it('offers "Acknowledge this alert only" on a group ack', async () => {
    getActionScope.mockResolvedValueOnce(GROUP_SCOPE);
    const p = mount(ack);
    await waitFor(() => screen.getByText(GROUP_SCOPE.sentence));
    fireEvent.click(screen.getByRole('button', { name: /^Acknowledge$/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge this alert only' }));
    expect(p.onExecute).toHaveBeenCalledWith('alert');
  });

  it('says what an escalate does and writes nothing on Cancel', () => {
    getActionScope.mockClear();
    const p = mount(esc);
    expect(screen.getByTestId('action-scope').textContent).toBe(
      'Open one Security Onion case for this alert.',
    );
    fireEvent.click(screen.getByRole('button', { name: /Escalate to case/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(p.onExecute).not.toHaveBeenCalled();
    expect(screen.queryByTestId('action-confirm')).toBeNull();
    // An escalate needs no count from the server.
    expect(getActionScope).not.toHaveBeenCalled();
  });

  // Review 2026-11-13, D2. A true positive on a hunt finding showed Escalate
  // off. The escalate of a finding now opens a case from the finding, so the
  // card names the finding and the confirm states the same write.
  it('states the case of a finding and the alerts it attaches, from the server', async () => {
    const sentence =
      'Open one Security Onion case for this finding. soc-ai attaches 3 alerts that the finding cites. Security Onion marks each attached alert escalated and acknowledged. soc-ai skips 2 alerts that the finding cites.';
    getActionScope.mockResolvedValueOnce({
      tool: 'escalate_to_case',
      scope: 'finding',
      count: 3,
      hosts: null,
      held: 2,
      rangeLabel: '',
      sentence,
    });
    const p = mount(esc, { findingCase: true });
    await waitFor(() => expect(screen.getByTestId('action-scope').textContent).toBe(sentence));
    fireEvent.click(screen.getByRole('button', { name: /Escalate to case/ }));
    expect(p.onExecute).not.toHaveBeenCalled();
    expect(screen.getByTestId('action-confirm').textContent).toContain(
      `This writes to Security Onion. ${sentence}`,
    );
    // The button states the effect: one case, and three alerts.
    fireEvent.click(screen.getByRole('button', { name: 'Open the case and attach 3 alerts' }));
    expect(p.onExecute).toHaveBeenCalledWith('group');
  });

  // A create that failed with a 5xx left the finding with no recorded result,
  // and each press was refused for good. The blocked state now has one
  // control, Try again, behind a confirm that says to look in Cases first.
  it('offers Try again only when an earlier press has no result', async () => {
    const blocked = {
      tool: 'escalate_to_case',
      scope: 'finding' as const,
      count: 0,
      hosts: null,
      held: 0,
      rangeLabel: '',
      sentence: 'An earlier press started a Security Onion case for this finding, and soc-ai has no record of the result.',
      retry: true,
      retrySentence: 'Look at the Cases page of Security Onion first. Press Try again only if no case has the title "T".',
    };
    getActionScope.mockResolvedValueOnce(blocked);
    const p = mount(esc, { findingCase: true });
    await waitFor(() => expect(screen.getByTestId('action-scope').textContent).toBe(blocked.sentence));
    expect(screen.queryByRole('button', { name: /Escalate to case/ })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    // The first click writes nothing. The confirm says to look first.
    expect(p.onExecute).not.toHaveBeenCalled();
    const confirm = screen.getByTestId('action-confirm');
    expect(confirm.textContent).toContain(blocked.retrySentence);
    fireEvent.click(within(confirm).getByRole('button', { name: 'Try again' }));
    expect(p.onExecute).toHaveBeenCalledWith('group', { retry: true });
  });

  it('offers no Try again on a finding with no blocked press', async () => {
    getActionScope.mockResolvedValueOnce({
      tool: 'escalate_to_case',
      scope: 'finding',
      count: 1,
      hosts: null,
      held: 0,
      rangeLabel: '',
      sentence: 'Open one Security Onion case for this finding. soc-ai attaches 1 alert that the finding cites.',
      retry: false,
    });
    const p = mount(esc, { findingCase: true });
    await waitFor(() => screen.getByText(/attaches 1 alert/));
    expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: /Escalate to case/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Open the case and attach 1 alert' }));
    expect(p.onExecute).toHaveBeenCalledWith('group');
  });

  it('names the finding while the server counts, and when it cannot count', async () => {
    getActionScope.mockRejectedValueOnce(new Error('grid down'));
    mount(esc, { findingCase: true });
    expect(screen.getByTestId('action-scope').textContent).toContain(
      'Open one Security Onion case for this finding.',
    );
    await waitFor(() =>
      expect(screen.getByTestId('action-scope').textContent).toBe(
        'Open one Security Onion case for this finding. soc-ai could not count the alerts that the case attaches.',
      ),
    );
  });

  it('labels the case of a finding by the count of the server', () => {
    const finding = { tool: 'escalate_to_case', scope: 'finding' as const, hosts: null, held: 0, rangeLabel: '', sentence: 's' };
    expect(confirmLabel('escalate', { ...finding, count: 1 })).toBe('Open the case and attach 1 alert');
    expect(confirmLabel('escalate', { ...finding, count: 0 })).toBe('Open the case');
    expect(confirmLabel('escalate', null)).toBe('Open the case');
  });

  // Negative control: the acknowledge of a finding stays off, with the
  // reason of the server.
  it('keeps the acknowledge of a finding off', () => {
    const blocked = { ...ack, blockedReason: 'A promoted finding has no Security Onion alert to act on.' };
    mount(blocked, { findingCase: true });
    expect(screen.getByTestId('action-blocked').textContent).toBe(blocked.blockedReason);
    expect(screen.getByRole('button', { name: /^Acknowledge$/ })).toBeDisabled();
  });

  it('confirms a dismissal before it stores it', () => {
    const p = mount(esc);
    fireEvent.click(screen.getByRole('button', { name: /Dismiss/ }));
    expect(p.onDismiss).not.toHaveBeenCalled();
    expect(screen.getByTestId('dismiss-confirm').textContent).toContain('You can undo it.');
    fireEvent.click(screen.getByRole('button', { name: /Confirm dismiss/ }));
    expect(p.onDismiss).toHaveBeenCalledTimes(1);
  });

  it('shows who dismissed and when, with an undo', () => {
    const at = '2026-10-06T11:09:00+00:00';
    const p = mount(esc, { dismissal: { by: 'alice', at } });
    expect(screen.getByTestId('action-dismissed').textContent).toContain(
      `Dismissed by alice at ${clockTime(at)}.`,
    );
    fireEvent.click(screen.getByRole('button', { name: /Undo/ }));
    expect(p.onUndoDismiss).toHaveBeenCalledTimes(1);
    // A dismissed card offers no write.
    expect(screen.queryByRole('button', { name: /Escalate to case/ })).toBeNull();
  });

  it('turns every button off when a newer run replaced the run', () => {
    mount(esc, { lockedReason: 'A newer investigation replaced this one.' });
    expect(screen.getByRole('button', { name: /Escalate to case/ })).toBeDisabled();
    expect(screen.getByRole('button', { name: /Dismiss/ })).toBeDisabled();
  });

  // Dogfood 2026-10-19, R1-I1 follow-up. The card and the row of the
  // pending-action list read one server rule (analyst_verdict_block), and
  // the card shows the reason the server states.
  it('turns the write off and states the reason when it acts against an analyst verdict', () => {
    const reason =
      'ana set the verdict of this alert to false positive. This run reached true positive. Override the verdict of this run to act.';
    const p = mount({ ...esc, blockedReason: reason });
    const write = screen.getByRole('button', { name: /Escalate to case/ });
    expect(write).toBeDisabled();
    expect(write.getAttribute('title')).toBe(reason);
    expect(screen.getByTestId('action-blocked').textContent).toBe(reason);
    fireEvent.click(write);
    expect(screen.queryByTestId('action-confirm')).toBeNull();
    expect(p.onExecute).not.toHaveBeenCalled();
    // Dismiss writes nothing to Security Onion. It stays on.
    expect(screen.getByRole('button', { name: /Dismiss/ })).toBeEnabled();
  });

  it('does not count the alerts of an ack that the rule turns off', () => {
    getActionScope.mockClear();
    mount({
      ...ack,
      blockedReason:
        'ana set the verdict of this alert to true positive. soc-ai does not acknowledge an alert with that verdict.',
    });
    expect(screen.getByRole('button', { name: /^Acknowledge$/ })).toBeDisabled();
    expect(getActionScope).not.toHaveBeenCalled();
  });

  it('NEGATIVE CONTROL: no reason from the server keeps the write on', () => {
    mount({ ...esc, blockedReason: null });
    expect(screen.getByRole('button', { name: /Escalate to case/ })).toBeEnabled();
    expect(screen.queryByTestId('action-blocked')).toBeNull();
  });

  it('falls back to a plain sentence when the count does not arrive', async () => {
    getActionScope.mockRejectedValueOnce(new Error('down'));
    await act(async () => {
      mount(ack);
    });
    await waitFor(() =>
      expect(screen.getByTestId('action-scope').textContent).toContain(
        'soc-ai could not count the alerts.',
      ),
    );
  });

  // Verify 2026-10-20, V3-N2. The alert of the range was on two cases, and
  // the card said "Open one Security Onion case for this alert.". The execute
  // route then opened no case. The card names and links each case, like the
  // Alerts escalate confirm.
  const CASES = [
    { id: 'case-a', url: 'https://so.example/#/case/case-a' },
    { id: 'case-b', url: 'https://so.example/#/case/case-b' },
  ];

  it('names and links each case the alert is already on', () => {
    const p = mount(esc, { cases: CASES, casesComplete: true });
    const line = screen.getByTestId('action-cases');
    expect(line.textContent).toBe('The alert is already on cases case-a, case-b.');
    expect(screen.getByRole('link', { name: 'case-a' })).toHaveAttribute(
      'href',
      'https://so.example/#/case/case-a',
    );
    expect(screen.getByRole('link', { name: 'case-b' })).toHaveAttribute(
      'href',
      'https://so.example/#/case/case-b',
    );
    expect(screen.getByTestId('action-scope').textContent).toBe(
      'soc-ai opens no second case. The press records this action as done.',
    );
    fireEvent.click(screen.getByRole('button', { name: /Escalate to case/ }));
    const confirm = screen.getByTestId('action-confirm');
    // The press writes nothing to Security Onion, so the confirm says no write.
    expect(confirm.textContent).not.toContain('This writes to Security Onion.');
    expect(confirm.textContent).toContain('The alert is already on cases case-a, case-b.');
    fireEvent.click(screen.getByRole('button', { name: 'Record as done' }));
    expect(p.onExecute).toHaveBeenCalledWith('group');
  });

  it('says found for a case list the grid did not confirm', () => {
    mount(esc, { cases: CASES.slice(0, 1), casesComplete: false });
    expect(screen.getByTestId('action-cases').textContent).toBe(
      'soc-ai found the alert on case case-a.',
    );
  });

  it('names the cases beside the reason when the write is off', () => {
    const reason =
      'A promoted lead uses this document as its anchor. The document is not a Security Onion alert.';
    mount({ ...esc, blockedReason: reason }, { cases: CASES, casesComplete: true });
    expect(screen.getByRole('button', { name: /Escalate to case/ })).toBeDisabled();
    expect(screen.getByTestId('action-blocked').textContent).toBe(reason);
    expect(screen.getByTestId('action-cases').textContent).toBe(
      'The alert is already on cases case-a, case-b.',
    );
  });

  it('NEGATIVE CONTROL: an ack names no case', () => {
    getActionScope.mockResolvedValueOnce(GROUP_SCOPE);
    mount(ack, { cases: CASES, casesComplete: true });
    expect(screen.queryByTestId('action-cases')).toBeNull();
  });

  it('asks to dismiss a recommended action', () => {
    mount(esc);
    fireEvent.click(screen.getByRole('button', { name: /Dismiss/ }));
    expect(screen.getByTestId('dismiss-confirm').textContent).toContain(
      'Dismiss this recommended action. soc-ai records your name and the time. You can undo it.',
    );
  });

  it('labels the confirm with the count', () => {
    expect(confirmLabel('ack', { ...GROUP_SCOPE, scope: 'group', count: 1 })).toBe('Acknowledge 1 alert');
    expect(confirmLabel('ack', null)).toBe('Acknowledge this alert');
    expect(confirmLabel('escalate', null)).toBe('Open the case');
  });
});

describe('ActionCard campaign note', () => {
  // A campaign holds the investigation: the analyst decides once, on the
  // campaign. The write stays executable in part A.
  const held = {
    id: 7,
    title: 'actor-a against web-1',
    status: 'open' as const,
    stage: 'action' as const,
    differs: false,
    decision: null,
    waitsSince: '2026-10-24T00:40:00Z',
  };
  const routed = (action: RecommendedAction, campaign: typeof held | Omit<typeof held, 'decision' | 'waitsSince'>) => {
    const props = { action, index: 0, invId: 'INV-1', onExecute: vi.fn(), onDismiss: vi.fn(), onUndoDismiss: vi.fn(), campaign };
    render(
      <MemoryRouter>
        <ActionCard {...props} />
      </MemoryRouter>,
    );
  };

  it('names the campaign and sends the analyst to it, and keeps the write', () => {
    routed(esc, held);
    const note = screen.getByTestId('action-campaign');
    expect(note).toHaveTextContent('Part of the campaign actor-a against web-1. Decide on the campaign.');
    expect(within(note).getByRole('link', { name: 'Open the campaign' })).toHaveAttribute('href', '/campaigns/7');
    expect(screen.getByRole('button', { name: /Escalate to case/ })).toBeEnabled();
  });

  it('states no note for a verdict that differs, nor for a server with no decision field', () => {
    // NEGATIVE CONTROL. A verdict that differs waits under its own rules.
    routed(esc, { ...held, differs: true });
    expect(screen.queryByTestId('action-campaign')).toBeNull();
  });

  it('states no note for a link of an older server', () => {
    const { decision: _d, waitsSince: _w, ...older } = held;
    routed(esc, older);
    expect(screen.queryByTestId('action-campaign')).toBeNull();
  });

  // The server sends the note of the campaign too. The card builds the same
  // sentence with the link, so it states the note once.
  const noted: RecommendedAction = {
    ...esc,
    noteCode: 'campaign',
    note: 'Part of the campaign actor-a against web-1. Decide on the campaign.',
    noteHref: '/campaigns/7',
  };

  it('states the campaign note of the server once', () => {
    routed(noted, held);
    expect(screen.getAllByText(/Decide on the campaign\./)).toHaveLength(1);
    expect(screen.queryByTestId('action-note')).toBeNull();
  });

  it('states the server note as plain text when the card builds no sentence for it', () => {
    // A link of an older server: the card builds no campaign sentence.
    const { decision: _d, waitsSince: _w, ...older } = held;
    routed(noted, older);
    expect(screen.getByTestId('action-note')).toHaveTextContent(
      'Part of the campaign actor-a against web-1. Decide on the campaign.',
    );
  });

  it('states the note of a code that the console does not know as plain text', () => {
    routed({ ...esc, noteCode: 'authorization', note: 'An authorization covers this action.', noteHref: null }, {
      ...held,
      differs: true,
    });
    const note = screen.getByTestId('action-note');
    expect(note).toHaveTextContent('An authorization covers this action.');
    expect(within(note).queryByRole('link')).toBeNull();
    expect(screen.queryByTestId('action-campaign')).toBeNull();
  });

  // NEGATIVE CONTROL. An action with no note states none.
  it('states no note for an action with no note', () => {
    routed(esc, { ...held, differs: true });
    expect(screen.queryByTestId('action-note')).toBeNull();
  });
});

describe('ActionCard case on the campaign', () => {
  // A campaign holds the investigation: its one case opens on the campaign.
  // The server blocks the Escalate of the investigation with the code campaign.
  const held = {
    id: 7,
    title: 'actor-a against web-1',
    status: 'open' as const,
    stage: 'action' as const,
    differs: false,
    decision: null,
    waitsSince: '2026-10-24T00:40:00Z',
  };
  const blocked: RecommendedAction = {
    ...esc,
    blockedReason: 'Open the case on the campaign.',
    noteCode: 'campaign',
    note: 'Part of the campaign actor-a against web-1. Decide on the campaign.',
    noteHref: '/campaigns/7',
  };
  const routed = (action: RecommendedAction, campaign: object | null) => {
    const props = {
      action,
      index: 0,
      invId: 'INV-1',
      onExecute: vi.fn(),
      onDismiss: vi.fn(),
      onUndoDismiss: vi.fn(),
      campaign: campaign as typeof held | null,
    };
    render(
      <MemoryRouter>
        <ActionCard {...props} />
      </MemoryRouter>,
    );
    return props;
  };

  it('reads Open the case on the campaign with the link, and the Escalate is no button', () => {
    const { onExecute } = routed(blocked, held);
    const line = screen.getByTestId('action-campaign-case');
    expect(line).toHaveTextContent('Part of the campaign actor-a against web-1. Open the case on the campaign.');
    expect(within(line).getByRole('link', { name: 'Open the campaign' })).toHaveAttribute('href', '/campaigns/7');
    expect(screen.queryByRole('button', { name: /Escalate to case/ })).toBeNull();
    // The card states the case once, and no second campaign note.
    expect(screen.getAllByText(/Open the case on the campaign\./)).toHaveLength(1);
    expect(screen.queryByTestId('action-blocked')).toBeNull();
    expect(screen.queryByTestId('action-campaign')).toBeNull();
    expect(screen.queryByTestId('action-note')).toBeNull();
    // The card offers no write, so it states no scope of one.
    expect(screen.queryByTestId('action-scope')).toBeNull();
    // Dismiss writes nothing to Security Onion, so it stays.
    expect(screen.getByRole('button', { name: /Dismiss/ })).toBeEnabled();
    expect(onExecute).not.toHaveBeenCalled();
    const text = screen.getByTestId('action-card-0').textContent ?? '';
    expect(text).not.toMatch(/\b(runs?|members?|kinds?)\b/i);
  });

  it('reads the decision of a closed campaign with the link, and asks for nothing (OW4)', () => {
    const closed = { ...held, decision: 'closed' as const, decidedAt: '2026-11-15T14:02:00Z', waitsSince: null };
    routed(blocked, closed);
    const line = screen.getByTestId('action-campaign-case');
    expect(line).toHaveTextContent(
      'Part of the campaign actor-a against web-1. The analyst closed the campaign on 2026-11-15 14:02 UTC. No action waits.',
    );
    expect(line).not.toHaveTextContent('Open the case on the campaign.');
    expect(within(line).getByRole('link', { name: 'Open the campaign' })).toHaveAttribute('href', '/campaigns/7');
    expect(screen.queryByRole('button', { name: /Escalate to case/ })).toBeNull();
  });

  it('reads the decision on the note of another action of a decided campaign', () => {
    getActionScope.mockResolvedValue(GROUP_SCOPE);
    const decided = { ...held, decision: 'case' as const, decidedAt: '2026-11-15T14:02:00Z', waitsSince: null };
    routed(ack, decided);
    expect(screen.getByTestId('action-campaign')).toHaveTextContent(
      'Part of the campaign actor-a against web-1. The analyst opened a case for the campaign on 2026-11-15 14:02 UTC. No action waits.',
    );
  });

  it('uses the link of the server when the card has no campaign link', () => {
    const { decision: _d, waitsSince: _w, ...older } = held;
    routed(blocked, older);
    const line = screen.getByTestId('action-campaign-case');
    expect(line).toHaveTextContent('Open the case on the campaign.');
    expect(within(line).getByRole('link', { name: 'Open the campaign' })).toHaveAttribute('href', '/campaigns/7');
    expect(screen.queryByRole('button', { name: /Escalate to case/ })).toBeNull();
  });

  it('keeps the Escalate of an investigation in no campaign', () => {
    // NEGATIVE CONTROL: no campaign, no block, a button that writes.
    routed(esc, null);
    expect(screen.queryByTestId('action-campaign-case')).toBeNull();
    expect(screen.getByRole('button', { name: /Escalate to case/ })).toBeEnabled();
  });

  it('keeps a block of another rule as an off button with its reason', () => {
    // NEGATIVE CONTROL: a verdict that differs waits under its own rules.
    routed({ ...esc, blockedReason: 'An analyst set the verdict to false positive.' }, { ...held, differs: true });
    expect(screen.queryByTestId('action-campaign-case')).toBeNull();
    expect(screen.getByRole('button', { name: /Escalate to case/ })).toBeDisabled();
    expect(screen.getByTestId('action-blocked')).toHaveTextContent('An analyst set the verdict to false positive.');
  });

  it('keeps the acknowledge of a held investigation a button', () => {
    getActionScope.mockResolvedValue(GROUP_SCOPE);
    routed({ ...ack, noteCode: 'campaign', note: blocked.note, noteHref: '/campaigns/7' }, held);
    expect(screen.queryByTestId('action-campaign-case')).toBeNull();
    expect(screen.getByRole('button', { name: /^Acknowledge$/ })).toBeEnabled();
  });
});
