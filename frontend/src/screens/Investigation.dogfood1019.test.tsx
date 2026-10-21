// Dogfood 2026-10-19 (R2), the investigation page.
//
// R2-D1 / R2-I5: Re-run on a run that carries an analyst verdict replaced the
// verdict with one click. The page now asks first and names the verdict.
// R2-D4: a locked, in-flight-superseded or permanently failed record kept
// Re-run and Override enabled. R2-D5: an unresolved citation read like a
// resolved one, and a resolved tool citation did not render. R2-D10: every
// true positive said "lateral movement". R2-D22: the label over an analyst
// verdict said "soc-ai verdict". Each block has a control beside it.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

const startHunt = vi.fn();
const requestMoreInfo = vi.fn();

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
  getActionScope: vi.fn().mockResolvedValue(null),
  startHunt: (...args: unknown[]) => startHunt(...args),
  requestMoreInfo: (...args: unknown[]) => requestMoreInfo(...args),
}));

import { Investigation, SUPERSEDED_LOCK } from './Investigation';

const inv = (over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET WEB_SERVER Possible SQL Injection',
    kind: 'suricata',
    host: '192.0.2.42',
    ip: '198.51.100.77',
    verdict: 'false_positive',
    conf: 0.8,
    rationale: 'The request is a scanner probe.',
    summary: [{ t: 'text', v: 'x' }],
    status: 'complete',
    elapsedLabel: '1m',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

const mount = (i: Inv, onReHunt = vi.fn()) =>
  render(
    <MemoryRouter>
      <Investigation inv={i} layout="page" onReHunt={onReHunt} />
    </MemoryRouter>,
  );

const rerunButton = () => screen.getByRole('button', { name: 'Re-run investigation' });
const overrideButton = () => screen.getByRole('button', { name: /Override verdict/ });

const analystTp = (): Partial<Inv> => ({
  verdict: 'true_positive',
  conf: 1,
  resolution: {
    original_verdict: 'false_positive',
    resolved_via: 'manual',
    resolved_by: 'alice',
    resolved_at: new Date().toISOString(),
  },
});

beforeEach(() => {
  startHunt.mockReset();
  startHunt.mockResolvedValue('INV-NEW');
  requestMoreInfo.mockReset();
  requestMoreInfo.mockResolvedValue('INV-ANSWER');
});

describe('R2-D1 / R2-I5: a re-run asks before it replaces an analyst verdict', () => {
  it('names the verdict, and Keep the analyst verdict starts nothing', () => {
    mount(inv(analystTp()));
    fireEvent.click(rerunButton());
    const dialog = screen.getByRole('dialog', { name: 'Re-run investigation' });
    expect(dialog.textContent).toContain('alice set the verdict of this alert to true positive.');
    fireEvent.click(screen.getByRole('button', { name: 'Keep the analyst verdict' }));
    expect(screen.queryByRole('dialog', { name: 'Re-run investigation' })).toBeNull();
    expect(startHunt).not.toHaveBeenCalled();
  });

  it('Replace the analyst verdict starts the run', async () => {
    const onReHunt = vi.fn();
    mount(inv(analystTp()), onReHunt);
    fireEvent.click(rerunButton());
    fireEvent.click(screen.getByRole('button', { name: 'Replace the analyst verdict' }));
    await waitFor(() => expect(onReHunt).toHaveBeenCalledWith('INV-NEW'));
    expect(startHunt).toHaveBeenCalledWith('ev-1', undefined);
  });

  it('control: a model verdict re-runs with no question', async () => {
    const onReHunt = vi.fn();
    mount(inv(), onReHunt);
    fireEvent.click(rerunButton());
    expect(screen.queryByRole('dialog', { name: 'Re-run investigation' })).toBeNull();
    await waitFor(() => expect(onReHunt).toHaveBeenCalledWith('INV-NEW'));
  });
});

describe('R2-D22: the label names whose verdict the card shows', () => {
  it('reads Analyst verdict over an override', () => {
    mount(inv(analystTp()));
    expect(screen.getByTestId('verdict-source').textContent).toBe('Analyst verdict');
  });

  it('control: a model verdict reads soc-ai verdict', () => {
    mount(inv());
    expect(screen.getByTestId('verdict-source').textContent).toBe('soc-ai verdict');
  });
});

describe('R2-D4: a record keeps its buttons off, with the reason', () => {
  it('a superseded record turns Re-run and Override off', () => {
    mount(
      inv({
        supersededBy: 'INV-NEW',
        supersededRun: { id: 'INV-NEW', status: 'complete', verdict: 'true_positive', conf: 0.7 },
      }),
    );
    expect(rerunButton()).toBeDisabled();
    expect(rerunButton().getAttribute('title')).toBe(SUPERSEDED_LOCK);
    expect(overrideButton()).toBeDisabled();
    expect(overrideButton().getAttribute('title')).toBe(SUPERSEDED_LOCK);
  });

  it('a newer run in flight turns them off before the press', () => {
    mount(inv({ supersededBy: 'INV-NEW', supersededRun: { id: 'INV-NEW', status: 'running' } }));
    expect(rerunButton()).toBeDisabled();
    expect(overrideButton()).toBeDisabled();
  });

  it('a permanent failure turns Re-run off and says why', () => {
    mount(
      inv({
        status: 'error',
        verdict: 'untriaged',
        failure: { cause: 'alert_not_found', hint: null, permanent: true },
      }),
    );
    const buttons = screen.getAllByRole('button', { name: 'Re-run investigation' });
    for (const b of buttons) {
      expect(b).toBeDisabled();
      expect(b.getAttribute('title')).toBe('A re-run cannot change the recorded cause.');
    }
  });

  it('control: the standing run keeps both buttons', () => {
    mount(inv());
    expect(rerunButton()).not.toBeDisabled();
    expect(overrideButton()).not.toBeDisabled();
  });
});

describe('R2-D5: cited evidence says what resolved', () => {
  it('marks an unresolved citation and shows a resolved tool citation', () => {
    mount(
      inv({
        citations: [
          { text: 'community_id_events.2.payload_printable', kind: 'path', target: 'community_id_events.2.payload_printable', resolved: false },
          { text: 'alert.rule_name', kind: 'path', target: 'alert.rule_name', resolved: true },
          { text: '(tool t_query_zeek_logs)', kind: 'tool', target: 't_query_zeek_logs', resolved: true },
        ],
      }),
    );
    const unresolved = screen.getByText('community_id_events.2.payload_printable');
    expect(unresolved.getAttribute('data-resolved')).toBe('false');
    expect(unresolved.getAttribute('title')).toContain('did not resolve');
    const resolved = screen.getByText('alert.rule_name');
    expect(resolved.getAttribute('data-resolved')).toBe('true');
    expect(screen.getByTestId('cited-tool').textContent).toContain('Zeek logs');
    expect(screen.getByTestId('cited-evidence').textContent).toContain('1 citation did not resolve.');
  });
});

describe('R2-D10: lateral movement only on an internal pair', () => {
  const tpGraph = (scope: Inv['graphScope']): Partial<Inv> => ({
    verdict: 'true_positive',
    graphScope: scope,
    nodes: [
      { id: '198.51.100.77', x: 20, y: 50, kind: 'host', label: '198.51.100.77' },
      { id: '192.0.2.42', x: 78, y: 50, kind: 'internal', label: '192.0.2.42' },
    ],
    edges: [{ from: '198.51.100.77', to: '192.0.2.42', kind: 'flow' }],
  });

  it('an inbound attack reads inbound', () => {
    mount(inv(tpGraph('inbound')));
    expect(screen.queryByText(/lateral movement/)).toBeNull();
    expect(screen.getAllByText(/inbound from an external source/).length).toBeGreaterThan(0);
  });

  it('control: an internal pair still reads lateral movement', () => {
    mount(
      inv({
        ...tpGraph('lateral'),
        nodes: [
          { id: '192.0.2.20', x: 20, y: 50, kind: 'compromised', label: '192.0.2.20' },
          { id: '192.0.2.40', x: 78, y: 50, kind: 'internal', label: '192.0.2.40' },
        ],
      }),
    );
    expect(screen.getAllByText(/lateral movement/).length).toBeGreaterThan(0);
  });
});

describe('R2-D21: the host context states its window', () => {
  const sig = (label: string) => ({ time: '', label, sev: '3×', tone: 'low', w: 40 });

  it('names the hours each side of the alert', () => {
    mount(
      inv({
        hostContextWindowHours: 24,
        hostContexts: [
          { ip: '192.0.2.20', end: 'source', asSource: [sig('ET POLICY fetch')], asDestination: [] },
        ],
      } as Partial<Inv>),
    );
    expect(
      screen.getByText('Alerts with this host as source within 24 hours of the alert'),
    ).toBeTruthy();
  });
});

describe('R2-D21: the alert details count states what it counts', () => {
  it('names the count as rule fires on the two ends, in the window', () => {
    mount(
      inv({
        hostContextWindowHours: 24,
        alert: {
          rule: 'ET X',
          sid: '1',
          classtype: 'c',
          category: 'k',
          src: '192.0.2.20:5',
          dst: '192.0.2.40:445',
          proto: 'TCP',
          action: 'allowed',
          time: new Date().toISOString(),
          count: 6,
        },
      } as Partial<Inv>),
    );
    expect(screen.getByText('rule fires')).toBeTruthy();
    expect(screen.getByText('6 on either end within 24 hours of the alert')).toBeTruthy();
  });
});

// ── Round 2 (V1-A2, V1-A3): one rule for every new run ──────────────────────
//
// A newer model run hid the analyst verdict on an earlier run of the alert:
// the page read "soc-ai verdict" and Re-run asked nothing (V1-A3). Request
// more info on a backtest replay started a live run, and that run replaced
// the live true positive of the alert with no word (V1-A2).

const onEarlierRun = (): Partial<Inv> => ({
  standingAnalystVerdict: {
    investigationId: 'INV-0',
    verdict: 'true_positive',
    by: 'alice',
    via: 'manual',
    at: new Date().toISOString(),
  },
});

const nmi = (over: Partial<Inv> = {}): Inv =>
  inv({ verdict: 'needs_more_info', conf: 0.5, openQuestions: ['Who logged in?'], ...over });

const requestInfoButton = () => screen.getByRole('button', { name: 'Request more info' });

describe('V1-A3: the analyst verdict on an earlier run stands and is named', () => {
  it('the page names the analyst verdict and links its run', () => {
    mount(inv(onEarlierRun()));
    const note = screen.getByTestId('standing-analyst-verdict');
    expect(note.textContent).toContain(
      'alice set the verdict of this alert to true positive on another run. That verdict stands.',
    );
    expect(within(note).getByRole('link', { name: 'Open that run.' }).getAttribute('href')).toBe(
      '/investigation/INV-0',
    );
    // This run's own verdict is the model's.
    expect(screen.getByTestId('verdict-source').textContent).toBe('soc-ai verdict');
  });

  it('Re-run asks first and names the verdict on the other run', () => {
    mount(inv(onEarlierRun()));
    fireEvent.click(rerunButton());
    const dialog = screen.getByRole('dialog', { name: 'Re-run investigation' });
    expect(dialog.textContent).toContain('alice set the verdict of this alert to true positive.');
    expect(dialog.textContent).toContain('That verdict is on another run of the alert.');
    fireEvent.click(screen.getByRole('button', { name: 'Keep the analyst verdict' }));
    expect(startHunt).not.toHaveBeenCalled();
  });

  it('Request more info asks first too, and starts on Replace', async () => {
    const onReHunt = vi.fn();
    mount(nmi(onEarlierRun()), onReHunt);
    fireEvent.click(requestInfoButton());
    expect(requestMoreInfo).not.toHaveBeenCalled();
    const dialog = screen.getByRole('dialog', { name: 'Request more info' });
    expect(dialog.textContent).toContain(
      'Request more info starts a new run. The new run can reach another verdict, and the alert then shows that verdict.',
    );
    fireEvent.click(within(dialog).getByRole('button', { name: 'Replace the analyst verdict' }));
    await waitFor(() => expect(onReHunt).toHaveBeenCalledWith('INV-ANSWER'));
    expect(requestMoreInfo).toHaveBeenCalledWith('INV-1');
  });

  it('Escape closes the confirm and starts nothing', () => {
    mount(inv(onEarlierRun()));
    fireEvent.click(rerunButton());
    const keep = screen.getByRole('button', { name: 'Keep the analyst verdict' });
    fireEvent.keyDown(keep, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(startHunt).not.toHaveBeenCalled();
  });

  it('control: the analyst run itself shows no note', () => {
    mount(
      inv({
        ...analystTp(),
        standingAnalystVerdict: {
          investigationId: 'INV-1',
          verdict: 'true_positive',
          by: 'alice',
          via: 'manual',
        },
      }),
    );
    expect(screen.queryByTestId('standing-analyst-verdict')).toBeNull();
    expect(screen.getByTestId('verdict-source').textContent).toBe('Analyst verdict');
  });

  it('control: a live needs-more-info run with no analyst verdict starts at once', async () => {
    const onReHunt = vi.fn();
    mount(nmi({ standingAnalystVerdict: null }), onReHunt);
    fireEvent.click(requestInfoButton());
    expect(screen.queryByRole('dialog')).toBeNull();
    await waitFor(() => expect(onReHunt).toHaveBeenCalledWith('INV-ANSWER'));
  });
});

describe('V1-A2: a new run from a replay names the live verdict it replaces', () => {
  const replay = (over: Partial<Inv> = {}): Inv =>
    nmi({
      meta: { model: 'm', ranBy: 'backtest', ranAt: new Date().toISOString(), toolCalls: 2, pivots: 1 },
      standingAnalystVerdict: null,
      alertLiveRun: { id: 'INV-LIVE', status: 'complete', verdict: 'true_positive', conf: 0.65 },
      ...over,
    });

  it('Request more info asks first, names the live verdict and what the new run becomes', async () => {
    const onReHunt = vi.fn();
    mount(replay(), onReHunt);
    fireEvent.click(requestInfoButton());
    const dialog = screen.getByRole('dialog', { name: 'Request more info' });
    const text = dialog.textContent ?? '';
    expect(text).toContain('This run is a backtest replay.');
    expect(text).toContain('The live verdict of the alert is true positive at 0.65.');
    expect(text).toContain(
      'Request more info starts a live run. The verdict of the new run becomes the live verdict of the alert.',
    );
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(requestMoreInfo).not.toHaveBeenCalled();

    fireEvent.click(requestInfoButton());
    fireEvent.click(screen.getByRole('button', { name: 'Start a live run' }));
    await waitFor(() => expect(onReHunt).toHaveBeenCalledWith('INV-ANSWER'));
  });

  it('Re-run on a replay asks the same question', () => {
    mount(replay({ verdict: 'false_positive', conf: 0.8, openQuestions: [] }));
    fireEvent.click(rerunButton());
    const dialog = screen.getByRole('dialog', { name: 'Re-run investigation' });
    expect(dialog.textContent).toContain(
      'A re-run starts a live run. The verdict of the new run becomes the live verdict of the alert.',
    );
    expect(startHunt).not.toHaveBeenCalled();
  });

  it('a replay whose alert has no live verdict says so', () => {
    mount(replay({ alertLiveRun: null }));
    fireEvent.click(requestInfoButton());
    expect(screen.getByRole('dialog').textContent).toContain('The alert has no live verdict.');
  });

  it('an analyst verdict on the alert keeps the analyst buttons on a replay', () => {
    mount(replay(onEarlierRun()));
    fireEvent.click(requestInfoButton());
    const dialog = screen.getByRole('dialog', { name: 'Request more info' });
    expect(dialog.textContent).toContain('alice set the verdict of this alert to true positive.');
    expect(dialog.textContent).toContain('This run is a backtest replay.');
    expect(within(dialog).getByRole('button', { name: 'Replace the analyst verdict' })).toBeTruthy();
  });
});
