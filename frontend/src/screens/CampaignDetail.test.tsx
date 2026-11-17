import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { CampaignDetail } from './CampaignDetail';
import { ShellProvider, useShell } from '../shell/ShellContext';

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api');
  return {
    ...actual,
    getCampaign: vi.fn(),
    reopenCampaign: vi.fn(),
    closeCampaign: vi.fn(),
    getCampaignCloseScope: vi.fn(),
    getCampaignCaseScope: vi.fn(),
    openCampaignCase: vi.fn(),
  };
});
import {
  ApiError,
  closeCampaign,
  getCampaign,
  getCampaignCaseScope,
  getCampaignCloseScope,
  openCampaignCase,
  reopenCampaign,
} from '../lib/api';
import { STAGE_COLOR } from '../lib/campaignViz';
import {
  ACTOR,
  CAMPAIGN,
  CAMPAIGN_CASE,
  CAMPAIGN_CASE_READY,
  CAMPAIGN_CLOSED,
  CAMPAIGN_HUNTED,
  CAMPAIGN_WAITS,
  EVENTS,
  PAIR,
  TARGET,
  earlierCampaign,
  pair,
} from '../test/campaign';

function CrumbProbe() {
  const { crumbName } = useShell();
  return <div data-testid="crumb-name">{crumbName ? `${crumbName.key}|${crumbName.name}` : 'none'}</div>;
}

function mount(at = '/campaigns/7') {
  return render(
    <MemoryRouter initialEntries={[at]}>
      <ShellProvider>
        <CrumbProbe />
        <Routes>
          <Route path="/campaigns/:id" element={<CampaignDetail />} />
        </Routes>
      </ShellProvider>
    </MemoryRouter>,
  );
}

/** The fold of a table, found by its button. */
function fold(title: string): HTMLElement {
  const button = screen.getByRole('button', { name: new RegExp(`^(Expand|Collapse) ${title}$`) });
  return button.closest('[data-open]') as HTMLElement;
}

/** Open a closed fold and give it back. */
function openFold(title: string): HTMLElement {
  fireEvent.click(screen.getByRole('button', { name: `Expand ${title}` }));
  return fold(title);
}

beforeEach(() => {
  vi.mocked(getCampaign).mockReset().mockResolvedValue(CAMPAIGN);
});

describe('CampaignDetail', () => {
  it('shows the header, the bottom line and the earlier campaign', async () => {
    mount();
    expect(await screen.findByRole('heading', { name: 'actor-a against web-1' })).toBeInTheDocument();
    expect(getCampaign).toHaveBeenCalledWith(7);
    const header = screen.getByTestId('campaign-header');
    expect(within(header).getByTestId('campaign-status')).toHaveTextContent('Open');
    const stage = within(header).getByTestId('campaign-stage');
    expect(stage).toHaveTextContent('Action on the target');
    // The dot of the chip wears the color of the stage on the graphics.
    expect(within(stage).getByTestId('campaign-stage-dot').style.background).toBe(STAGE_COLOR.action);
    expect(screen.getByTestId('campaign-period')).toHaveTextContent('2026-10-24 00:40 to 2026-10-28 22:44 UTC');
    const bottom = screen.getByTestId('campaign-bottom-line');
    expect(bottom).toHaveTextContent(CAMPAIGN.bottomLine);
    expect(bottom.className).toContain('text-[14px]');
    expect(screen.getByTestId('campaign-earlier')).toHaveTextContent(
      'The same machines formed an earlier campaign: actor-a against web-1 in October.',
    );
    expect(within(screen.getByTestId('campaign-earlier')).getByRole('link')).toHaveAttribute('href', '/campaigns/3');
    // The top bar names the campaign by its number.
    // An effect sets the name after the campaign loads. Wait for it.
    await waitFor(() => expect(screen.getByTestId('crumb-name')).toHaveTextContent('7|Campaign 7'));
    // A fresh campaign states no notice, and a live one names no merge.
    expect(screen.queryByRole('status')).toBeNull();
    expect(screen.queryByTestId('campaign-merged')).toBeNull();
  });

  it('states the facts of the grid under the bottom line', async () => {
    mount();
    const facts = await screen.findByTestId('campaign-facts');
    expect(facts).toHaveTextContent(
      '47 alerts of 3 rules. 1 hunt finding. 1,840 grid records between the machines.',
    );
    expect(
      screen.getByTestId('campaign-bottom-line').compareDocumentPosition(facts) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it('states the facts of the stored events when soc-ai could not read the grid', async () => {
    vi.mocked(getCampaign).mockResolvedValue({
      ...CAMPAIGN,
      events: { ...EVENTS, source: 'stored', alerts: 1, findings: 2, records: null },
    });
    mount();
    expect(await screen.findByTestId('campaign-facts')).toHaveTextContent(
      '1 alert event that the investigations hold. 2 hunt findings.',
    );
    // NEGATIVE CONTROL: the stored events state no grid record.
    expect(screen.getByTestId('campaign-facts')).not.toHaveTextContent('grid record');
  });

  it('states each authorization as a line of the header', async () => {
    mount();
    const header = await screen.findByTestId('campaign-header');
    const list = within(header).getByTestId('campaign-authorizations');
    const lines = within(list).getAllByRole('listitem');
    expect(lines).toHaveLength(2);
    expect(lines[0]).toHaveTextContent(
      'The authorization Red team test covers 3 of the 5 investigations. It expires 2026-11-20 09:00 UTC.',
    );
    expect(lines[1]).toHaveTextContent('The authorization Old test is revoked.');
    // Each line has its shield icon, and the lines follow the bottom line.
    for (const line of lines) expect(line.querySelector('svg')).not.toBeNull();
    expect(
      screen.getByTestId('campaign-bottom-line').compareDocumentPosition(list) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    // NEGATIVE CONTROL: no panel of its own holds the authorizations.
    expect(screen.queryByText('Authorized activity')).toBeNull();
  });

  it('shows the graphics first, then the seven folds in their order', async () => {
    mount();
    await screen.findByTestId('campaign-header');
    const parts = [
      screen.getByTestId('campaign-header'),
      screen.getByTestId('stage-ladder'),
      screen.getByTestId('attack-graph'),
      screen.getByTestId('campaign-timeline'),
      fold('Alerts'),
      fold('Findings'),
      fold('Machines'),
      fold('Related, not proven'),
      fold('Verdicts that differ'),
      fold('Detection record'),
      fold('Investigations'),
    ];
    for (let i = 1; i < parts.length; i++) {
      // Each part follows the one before it in the document.
      expect(parts[i - 1].compareDocumentPosition(parts[i]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    }
    expect(screen.getByText('Attack graph')).toBeInTheDocument();
    expect(screen.getByText('Timeline')).toBeInTheDocument();
    expect(screen.getAllByTestId('graph-node')).toHaveLength(3);
    expect(screen.getAllByTestId('timeline-mark').length).toBeGreaterThan(0);
    // NEGATIVE CONTROL: the waves section is gone. The timeline states the times.
    expect(screen.queryByText('Waves')).toBeNull();
  });

  it('starts each fold closed, with its count, and opens it on a click', async () => {
    mount();
    await screen.findByTestId('campaign-header');
    const counts: [string, string, string | null][] = [
      // Five distinct rule names between actor-a and web-1.
      ['Alerts', 'fold-alerts', '5'],
      ['Findings', 'fold-findings', '1'],
      ['Machines', 'fold-machines', '3'],
      // One investigation that needs more info, one session and one named host. The
      // false positive line adds nothing.
      ['Related, not proven', 'fold-related', '3'],
      ['Verdicts that differ', 'fold-differ', '1'],
      ['Detection record', 'fold-detection', null],
      ['Investigations', 'fold-investigations', '4'],
    ];
    for (const [title, testId, count] of counts) {
      const f = fold(title);
      expect(f).toHaveAttribute('data-testid', testId);
      expect(f).toHaveAttribute('data-open', 'false');
      const button = within(f).getByRole('button', { name: `Expand ${title}` });
      expect(button).toHaveAttribute('aria-expanded', 'false');
      if (count === null) expect(within(f).queryByTestId(`${testId}-count`)).toBeNull();
      else expect(within(f).getByTestId(`${testId}-count`)).toHaveTextContent(count);
    }
    // NEGATIVE CONTROL: a closed fold holds no table.
    expect(screen.queryByTestId('campaign-members')).toBeNull();
    expect(screen.queryByTestId('campaign-parties')).toBeNull();
    expect(screen.queryByTestId('campaign-alerts')).toBeNull();
    expect(screen.queryByTestId('campaign-findings')).toBeNull();

    const members = openFold('Investigations');
    expect(members).toHaveAttribute('data-open', 'true');
    expect(within(members).getByRole('button', { name: 'Collapse Investigations' })).toHaveAttribute(
      'aria-expanded',
      'true',
    );
    expect(within(members).getByTestId('campaign-members')).toBeInTheDocument();
    // The fold draws no panel inside its panel.
    expect(members.querySelectorAll('.rounded-panel')).toHaveLength(1);
    fireEvent.click(within(members).getByRole('button', { name: 'Collapse Investigations' }));
    expect(screen.queryByTestId('campaign-members')).toBeNull();
  });

  it('shows one alert row for each rule of each pair, the confirmed rules first, then by alerts', async () => {
    vi.mocked(getCampaign).mockResolvedValue({
      ...CAMPAIGN,
      events: {
        ...EVENTS,
        pairs: [
          PAIR,
          pair(TARGET.machineKey, 'net:192.0.2.30', {
            rules: [
              { name: 'ET POLICY SMB write', alerts: 2, firstAt: '2026-10-29T08:00:00Z', lastAt: '2026-10-29T08:05:00Z', verdict: 'needs_more_info' },
              { name: 'ET EXPLOIT PHP file upload', alerts: 1, firstAt: '2026-10-29T08:01:00Z', lastAt: '2026-10-29T08:01:00Z', verdict: 'true_positive' },
            ],
          }),
        ],
      },
    });
    mount();
    await screen.findByTestId('campaign-header');
    // Six distinct rule names: one rule is in both pairs.
    expect(within(fold('Alerts')).getByTestId('fold-alerts-count')).toHaveTextContent('6');
    const table = within(openFold('Alerts')).getByTestId('campaign-alerts');
    const head = within(table).getAllByRole('columnheader').map((h) => h.textContent);
    expect(head).toEqual(['Rule', 'Alerts', 'From', 'To', 'First', 'Last', 'soc-ai verdict']);
    const rows = within(table).getAllByTestId('alert-row');
    expect(rows.map((r) => [r.getAttribute('data-rule'), r.getAttribute('data-verdict')])).toEqual([
      ['ET EXPLOIT PHP file upload', 'true_positive'],
      ['ET SCAN Nmap', 'true_positive'],
      ['ET WEB PHP shell request', 'true_positive'],
      ['ET EXPLOIT PHP file upload', 'true_positive'],
      ['ET POLICY curl user agent', 'false_positive'],
      ['ET INFO HTTP request to a raw address', 'not_judged'],
      ['ET POLICY SMB write', 'needs_more_info'],
    ]);
    const first = rows[0];
    expect(first).toHaveTextContent('30');
    expect(within(first).getByRole('link', { name: 'actor-a' })).toHaveAttribute('href', '/hosts/agent%3Aactor-a');
    expect(within(first).getByRole('link', { name: 'web-1' })).toBeInTheDocument();
    expect(first).toHaveTextContent('2026-10-24 01:11 UTC');
    expect(first).toHaveTextContent('2026-10-24 01:19 UTC');
    // The verdict cell: the pill of the three verdicts, the dim words of a rule that no one judged.
    const verdict = (i: number) => within(rows[i]).getByTestId('alert-verdict');
    expect(verdict(0)).toHaveTextContent('True positive');
    expect(verdict(4)).toHaveTextContent('False positive');
    expect(verdict(6)).toHaveTextContent('Needs more info');
    expect(verdict(5)).toHaveTextContent('Not judged');
    expect(within(verdict(5)).getByText('Not judged').className).toContain('text-dim');
    // NEGATIVE CONTROL: a rule that no one judged wears no verdict pill.
    expect(verdict(5)).not.toHaveTextContent('True positive');
    // The machine beyond the first target has no party name, so its address reads.
    expect(within(rows[3]).getByRole('link', { name: '192.0.2.30' })).toBeInTheDocument();
  });

  it('shows the true positive findings with their hunt, impact and stage', async () => {
    mount();
    await screen.findByTestId('campaign-header');
    const table = within(openFold('Findings')).getByTestId('campaign-findings');
    const head = within(table).getAllByRole('columnheader').map((h) => h.textContent);
    expect(head).toEqual(['Time', 'Finding', 'Impact', 'Stage']);
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows.map((r) => r.getAttribute('data-testid'))).toEqual(['finding-run-shell']);
    const row = rows[0];
    expect(row).toHaveTextContent('2026-10-28 22:44:56 UTC');
    expect(within(row).getByRole('link', { name: 'Command execution through the web shell' })).toHaveAttribute(
      'href',
      '/investigation/run-shell',
    );
    expect(within(row).getByRole('link', { name: 'View hunt' })).toHaveAttribute('href', '/hunts/hunt-9');
    expect(within(row).getByTestId('impact-chip')).toHaveTextContent('Succeeded');
    expect(within(row).getByTestId('finding-stage')).toHaveTextContent('Action on the target');
    // NEGATIVE CONTROL: an alert investigation is no finding.
    expect(within(table).queryByTestId('finding-run-seed')).toBeNull();
  });

  it('renders no Alerts fold and no Findings fold with nothing to show', async () => {
    vi.mocked(getCampaign).mockResolvedValue({
      ...CAMPAIGN,
      members: CAMPAIGN.members.filter((m) => m.kind === 'alert'),
      events: { ...EVENTS, pairs: [pair(ACTOR.machineKey, TARGET.machineKey, { rules: [] })] },
    });
    mount();
    await screen.findByTestId('campaign-header');
    expect(screen.queryByTestId('fold-alerts')).toBeNull();
    expect(screen.queryByTestId('fold-findings')).toBeNull();
    expect(fold('Investigations')).toBeInTheDocument();
  });

  it('shows the machines, actors first, with coverage and the beyond mark', async () => {
    mount();
    await screen.findByTestId('campaign-header');
    const table = within(openFold('Machines')).getByTestId('campaign-parties');
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows[0]).toHaveAttribute('data-testid', `party-${ACTOR.machineKey}`);
    const actor = screen.getByTestId(`party-${ACTOR.machineKey}`);
    expect(within(actor).getByRole('link', { name: 'actor-a' })).toHaveAttribute('href', '/hosts/agent%3Aactor-a');
    expect(actor).toHaveTextContent('Actor');
    expect(actor).toHaveTextContent('192.0.2.11');
    expect(actor).toHaveTextContent('agent report');
    expect(actor).toHaveTextContent('This machine has an agent.');
    const target = screen.getByTestId(`party-${TARGET.machineKey}`);
    expect(target).toHaveTextContent('network record');
    expect(target).toHaveTextContent('This machine has no agent. soc-ai cannot read processes or files on it.');
    // NEGATIVE CONTROL: the first target carries no beyond mark.
    expect(within(target).queryByTestId('party-beyond')).toBeNull();
    const beyond = screen.getByTestId('party-net:192.0.2.30');
    expect(within(beyond).getByRole('link', { name: '192.0.2.30' })).toBeInTheDocument();
    expect(within(beyond).getByTestId('party-beyond')).toHaveTextContent('Beyond the first target');
    expect(beyond).toHaveTextContent('DHCP lease');
  });

  it('shows the investigations with their links, and leaves out the verdicts that differ', async () => {
    mount();
    await screen.findByTestId('campaign-header');
    const table = within(openFold('Investigations')).getByTestId('campaign-members');
    expect(within(table).getAllByRole('row')).toHaveLength(1 + 4);
    // NEGATIVE CONTROL: an investigation whose verdict differs is no row of this table.
    expect(within(table).queryByTestId('member-run-differs')).toBeNull();

    const seed = screen.getByTestId('member-run-seed');
    expect(seed).toHaveTextContent('2026-10-24 01:11:05 UTC');
    expect(seed).toHaveTextContent('Alert');
    expect(within(seed).getByRole('link', { name: 'ET EXPLOIT PHP file upload' })).toHaveAttribute(
      'href',
      '/investigation/run-seed',
    );
    expect(seed).toHaveTextContent('True positive');
    expect(within(seed).getByTestId('impact-chip')).toHaveTextContent('Attempted');
    expect(within(seed).getByTestId('member-stage')).toHaveTextContent('Attempt');
    expect(seed).toHaveTextContent('First confirmed attack');
    expect(within(seed).getByTestId('member-link-sentence')).toHaveTextContent(
      'This investigation is the first confirmed attack. It started the campaign.',
    );

    // A null impact and a null stage render nothing.
    const session = screen.getByTestId('member-run-session');
    expect(within(session).queryByTestId('impact-chip')).toBeNull();
    expect(within(session).getByTestId('member-stage').textContent).toBe('');
    expect(within(session).getByTestId('member-link-sentence')).toHaveTextContent(
      'This investigation shares the connection 1:abc= with the investigation "ET EXPLOIT PHP file upload".',
    );

    // A finding links to its investigation and to its hunt.
    const finding = screen.getByTestId('member-run-shell');
    expect(finding).toHaveTextContent('Finding');
    expect(within(finding).getByRole('link', { name: 'View hunt' })).toHaveAttribute('href', '/hunts/hunt-9');
    // NEGATIVE CONTROL: an alert investigation has no hunt link.
    expect(within(seed).queryByRole('link', { name: 'View hunt' })).toBeNull();

    // The actor sentence reads the machine name when the evidence names no machine.
    expect(within(screen.getByTestId('member-run-actor')).getByTestId('member-link-sentence')).toHaveTextContent(
      'The attacking machine actor-a is the source of this investigation and of the investigation "ET EXPLOIT PHP file upload".',
    );
  });

  it('filters the investigations by link', async () => {
    mount();
    await screen.findByTestId('campaign-header');
    const filter = within(openFold('Investigations')).getByTestId('members-filter');
    const buttons = within(filter).getAllByRole('button');
    expect(buttons.map((b) => b.textContent)).toEqual([
      'All 4',
      'First confirmed attack 1',
      'Same connection 1',
      'Same attacking machine 1',
      'Same records 1',
    ]);
    expect(within(filter).getByRole('button', { name: 'All 4' })).toHaveAttribute('aria-pressed', 'true');

    fireEvent.click(within(filter).getByRole('button', { name: 'Same connection 1' }));
    const table = screen.getByTestId('campaign-members');
    expect(within(table).getAllByRole('row')).toHaveLength(1 + 1);
    expect(within(table).getByTestId('member-run-session')).toBeInTheDocument();
    expect(within(filter).getByRole('button', { name: 'Same connection 1' })).toHaveAttribute('aria-pressed', 'true');

    fireEvent.click(within(filter).getByRole('button', { name: 'All 4' }));
    expect(within(table).getAllByRole('row')).toHaveLength(1 + 4);
  });

  it('opens the Investigations fold on a pick in the timeline, shows its investigations, and shows all again', async () => {
    const scroll = vi.fn();
    const proto = HTMLElement.prototype as { scrollIntoView?: (arg?: ScrollIntoViewOptions) => void };
    const before = proto.scrollIntoView;
    proto.scrollIntoView = scroll;
    try {
      mount();
      await screen.findByTestId('campaign-header');
      expect(fold('Investigations')).toHaveAttribute('data-open', 'false');
      // The first mark holds the three investigations of 2026-10-24 00:40 to 01:20.
      fireEvent.click(within(screen.getAllByTestId('timeline-mark')[0]).getByRole('button'));
      const members = fold('Investigations');
      expect(members).toHaveAttribute('data-open', 'true');
      // NEGATIVE CONTROL: a mark of the timeline does not open the Alerts fold.
      expect(fold('Alerts')).toHaveAttribute('data-open', 'false');
      expect(scroll).toHaveBeenCalledWith({ block: 'nearest', behavior: 'smooth' });
      expect(within(members).getByTestId('members-selection')).toHaveTextContent(
        'Showing 3 of 4 investigations: actor-a, 2026-10-24 00:40 to 01:20 UTC.',
      );
      const table = within(members).getByTestId('campaign-members');
      expect(within(table).getAllByRole('row').slice(1).map((r) => r.getAttribute('data-testid'))).toEqual([
        'member-run-seed',
        'member-run-session',
        'member-run-actor',
      ]);
      // NEGATIVE CONTROL: the finding of 2026-10-28 is out of the pick.
      expect(within(table).queryByTestId('member-run-shell')).toBeNull();
      // The link buttons count the investigations of the pick.
      const filter = within(members).getByTestId('members-filter');
      expect(within(filter).getAllByRole('button').map((b) => b.textContent)).toEqual([
        'All 3',
        'First confirmed attack 1',
        'Same connection 1',
        'Same attacking machine 1',
      ]);

      fireEvent.click(within(members).getByRole('button', { name: 'Show all investigations' }));
      expect(within(members).queryByTestId('members-selection')).toBeNull();
      expect(within(screen.getByTestId('campaign-members')).getAllByRole('row')).toHaveLength(1 + 4);
      // A cleared pick leaves the fold open.
      expect(fold('Investigations')).toHaveAttribute('data-open', 'true');
    } finally {
      proto.scrollIntoView = before;
    }
  });

  it('opens the Alerts fold on a machine picked on the attack graph, filters it, and scrolls to it', async () => {
    const scrolled: Element[] = [];
    const proto = HTMLElement.prototype as { scrollIntoView?: (arg?: ScrollIntoViewOptions) => void };
    const before = proto.scrollIntoView;
    proto.scrollIntoView = function (this: HTMLElement) {
      scrolled.push(this);
    };
    vi.mocked(getCampaign).mockResolvedValue({
      ...CAMPAIGN,
      events: {
        ...EVENTS,
        pairs: [
          PAIR,
          pair(TARGET.machineKey, 'net:192.0.2.30', {
            rules: [{ name: 'ET POLICY SMB write', alerts: 2, firstAt: '2026-10-29T08:00:00Z', lastAt: '2026-10-29T08:05:00Z', verdict: 'true_positive' }],
          }),
        ],
      },
    });
    try {
      mount();
      await screen.findByTestId('campaign-header');
      expect(fold('Alerts')).toHaveAttribute('data-open', 'false');
      fireEvent.click(screen.getByRole('button', { name: 'actor-a: show its alerts' }));
      const alerts = fold('Alerts');
      expect(alerts).toHaveAttribute('data-open', 'true');
      expect(scrolled).toEqual([alerts]);
      expect(within(alerts).getByTestId('alerts-selection')).toHaveTextContent('Showing 59 of 61 alerts: actor-a.');
      const rows = within(alerts).getAllByTestId('alert-row');
      expect(rows).toHaveLength(5);
      // NEGATIVE CONTROL: the rule between web-1 and 192.0.2.30 is out of the pick.
      expect(rows.map((r) => r.getAttribute('data-rule'))).not.toContain('ET POLICY SMB write');
      // NEGATIVE CONTROL: a machine pick does not open the Investigations fold.
      expect(fold('Investigations')).toHaveAttribute('data-open', 'false');
      fireEvent.click(within(alerts).getByRole('button', { name: 'Show all alerts' }));
      expect(within(alerts).queryByTestId('alerts-selection')).toBeNull();
      expect(within(alerts).getAllByTestId('alert-row')).toHaveLength(6);
      expect(fold('Alerts')).toHaveAttribute('data-open', 'true');
    } finally {
      proto.scrollIntoView = before;
    }
  });

  it('filters the Alerts fold to an arrow picked on the attack graph, and survives a runtime with no scroll', async () => {
    const proto = HTMLElement.prototype as { scrollIntoView?: unknown };
    const before = proto.scrollIntoView;
    proto.scrollIntoView = undefined;
    try {
      mount();
      await screen.findByTestId('campaign-header');
      fireEvent.click(screen.getByRole('button', { name: 'actor-a to web-1: 47 alerts.' }));
      const alerts = fold('Alerts');
      expect(alerts).toHaveAttribute('data-open', 'true');
      expect(within(alerts).getByTestId('alerts-selection')).toHaveTextContent(
        'Showing 59 of 59 alerts: actor-a to web-1.',
      );
      // A second click on the arrow clears the pick. The fold stays open.
      fireEvent.click(screen.getByRole('button', { name: 'actor-a to web-1: 47 alerts.' }));
      expect(within(alerts).queryByTestId('alerts-selection')).toBeNull();
      expect(fold('Alerts')).toHaveAttribute('data-open', 'true');
    } finally {
      proto.scrollIntoView = before;
    }
  });

  it('opens the Investigations fold on a machine pick when the campaign has no Alerts fold', async () => {
    vi.mocked(getCampaign).mockResolvedValue(earlierCampaign());
    mount();
    await screen.findByTestId('campaign-header');
    expect(screen.queryByTestId('fold-alerts')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'web-1: show its alerts' }));
    const members = fold('Investigations');
    expect(members).toHaveAttribute('data-open', 'true');
    expect(within(members).getByTestId('members-selection')).toHaveTextContent(
      'Showing 4 of 4 investigations: web-1.',
    );
  });

  it('shows the related candidates', async () => {
    mount();
    await screen.findByTestId('campaign-header');
    const related = within(openFold('Related, not proven')).getByTestId('campaign-related');
    const nmi = screen.getByTestId('related-run-run-nmi');
    expect(nmi).toHaveTextContent('Needs more info');
    expect(within(nmi).getByRole('link', { name: 'ET POLICY SSH session' })).toHaveAttribute(
      'href',
      '/investigation/run-nmi',
    );
    expect(nmi).toHaveTextContent('192.0.2.10 to 192.0.2.20');
    const session = screen.getByTestId('related-session');
    expect(session).toHaveTextContent('actor-a to web-1 port 22: 14 documents, 2026-10-23 03:10 to 03:40 UTC.');
    expect(within(session).getByRole('link', { name: 'web-1' })).toHaveAttribute('href', '/hosts/net%3A192.0.2.20');
    expect(screen.getByTestId('related-named')).toHaveTextContent(
      'cdn.example.test: named in 3 documents of the campaign. No stored document shows a target in a connection to it.',
    );
    expect(related).toHaveTextContent(
      'soc-ai judged 41 alerts from a target as false positive. They are no part of the campaign.',
    );
    expect(screen.queryByTestId('related-empty')).toBeNull();
  });

  it('keeps the related fold for the false positive line alone, with no count', async () => {
    vi.mocked(getCampaign).mockResolvedValue({
      ...CAMPAIGN,
      related: { needsMoreInfo: [], sessions: [], named: [], falsePositiveFromTargets: 2 },
    });
    mount();
    await screen.findByTestId('campaign-header');
    // A count of 0 beside visible content would contradict it.
    expect(within(fold('Related, not proven')).queryByTestId('fold-related-count')).toBeNull();
    expect(openFold('Related, not proven')).toHaveTextContent(
      'soc-ai judged 2 alerts from a target as false positive. They are no part of the campaign.',
    );
  });

  it('shows the verdicts that differ with the sentence that the verdict stands', async () => {
    mount();
    await screen.findByTestId('campaign-header');
    openFold('Verdicts that differ');
    const row = screen.getByTestId('differs-run-differs');
    expect(row).toHaveTextContent('False positive');
    expect(within(row).getByRole('link', { name: 'ET POLICY curl user agent' })).toHaveAttribute(
      'href',
      '/investigation/run-differs',
    );
    expect(row).toHaveTextContent('This investigation is on a session of the campaign. Its verdict stands.');
  });

  it('shows the detection record, lowest stage first', async () => {
    mount();
    await screen.findByTestId('campaign-header');
    const record = within(openFold('Detection record')).getByTestId('detection-record');
    const rows = within(record).getAllByRole('listitem');
    expect(rows.map((r) => r.getAttribute('data-testid'))).toEqual(['detection-attempt', 'detection-action']);
    expect(rows[0]).toHaveTextContent('Attempt');
    expect(rows[0]).toHaveTextContent('Alert saw it first. The verdict came 3m 19s after the event.');
    expect(rows[1]).toHaveTextContent('Action on the target');
    expect(rows[1]).toHaveTextContent('Scheduled hunt saw it first. The verdict came 2h 00m after the event.');
  });

  it('renders no fold whose list is empty', async () => {
    vi.mocked(getCampaign).mockResolvedValue({
      ...CAMPAIGN,
      earlierCampaign: null,
      stage: null,
      authorizations: [],
      members: CAMPAIGN.members.filter((m) => !m.verdictDiffers),
      related: { needsMoreInfo: [], sessions: [], named: [], falsePositiveFromTargets: 0 },
      detection: [],
    });
    mount();
    await screen.findByTestId('campaign-header');
    expect(screen.queryByTestId('campaign-authorizations')).toBeNull();
    expect(screen.queryByTestId('fold-related')).toBeNull();
    expect(screen.queryByTestId('fold-differ')).toBeNull();
    expect(screen.queryByTestId('fold-detection')).toBeNull();
    expect(screen.queryByTestId('campaign-earlier')).toBeNull();
    expect(within(screen.getByTestId('campaign-header')).queryByTestId('campaign-stage')).toBeNull();
    // NEGATIVE CONTROL: the graphics and the folds with rows stay.
    expect(screen.getByTestId('stage-ladder')).toBeInTheDocument();
    expect(screen.getByTestId('attack-graph')).toBeInTheDocument();
    expect(fold('Alerts')).toBeInTheDocument();
    expect(fold('Findings')).toBeInTheDocument();
    expect(fold('Investigations')).toBeInTheDocument();
    expect(fold('Machines')).toBeInTheDocument();
  });

  it('names the campaign that holds a merged campaign, with a link', async () => {
    vi.mocked(getCampaign).mockResolvedValue({
      ...CAMPAIGN,
      status: 'merged',
      mergedInto: 3,
      earlierCampaign: null,
      authorizations: [],
      ladder: [],
      parties: [],
      waves: [],
      members: [],
      related: { needsMoreInfo: [], sessions: [], named: [], falsePositiveFromTargets: 0 },
      detection: [],
      graph: { edges: [] },
    });
    mount();
    const merged = await screen.findByTestId('campaign-merged');
    expect(merged).toHaveTextContent('This campaign is part of campaign 3.');
    expect(within(merged).getByRole('link', { name: 'campaign 3' })).toHaveAttribute('href', '/campaigns/3');
    expect(screen.getByTestId('campaign-status')).toHaveTextContent('Merged');
    // A merged campaign has empty lists. The page shows no graphic and no fold.
    expect(screen.queryByTestId('stage-ladder')).toBeNull();
    expect(screen.queryByTestId('attack-graph')).toBeNull();
    expect(screen.queryByTestId('campaign-timeline')).toBeNull();
    expect(screen.queryByRole('button', { name: /^Expand / })).toBeNull();
  });

  it('draws the page from a server of the earlier release with no graph', async () => {
    const { graph: _graph, ...earlier } = CAMPAIGN;
    vi.mocked(getCampaign).mockResolvedValue(earlier as typeof CAMPAIGN);
    mount();
    await screen.findByTestId('campaign-header');
    // The graph draws the machines with no arrow. The timeline reads the events.
    expect(screen.getAllByTestId('graph-node')).toHaveLength(3);
    expect(screen.getAllByTestId('graph-link').every((l) => l.getAttribute('data-related') === 'true')).toBe(true);
    expect(screen.getAllByTestId('timeline-mark').length).toBeGreaterThan(0);
  });

  it('draws the page from a server of the earlier release with none of the event fields', async () => {
    vi.mocked(getCampaign).mockResolvedValue(earlierCampaign());
    mount();
    await screen.findByTestId('campaign-header');
    // The header states no facts, and the timeline and the Alerts fold do not render.
    expect(screen.queryByTestId('campaign-facts')).toBeNull();
    expect(screen.queryByTestId('campaign-timeline')).toBeNull();
    expect(screen.queryByTestId('fold-alerts')).toBeNull();
    // The arrow reads its finding. The ladder states no headline and no evidence.
    expect(screen.getAllByTestId('graph-link-label').map((l) => l.textContent)).toEqual(['1 finding']);
    expect(screen.queryAllByTestId('ladder-headline')).toHaveLength(0);
    expect(screen.queryAllByTestId('ladder-evidence')).toHaveLength(0);
    // NEGATIVE CONTROL: the parts that the earlier server feeds stay.
    expect(screen.getByTestId('stage-ladder')).toBeInTheDocument();
    expect(screen.getAllByTestId('graph-node')).toHaveLength(3);
    expect(fold('Findings')).toBeInTheDocument();
    expect(fold('Investigations')).toBeInTheDocument();
    expect(screen.queryByText(/Could not load/)).toBeNull();
  });

  it('puts the fold of the leads and the hunts after the findings, with its two counts', async () => {
    vi.mocked(getCampaign).mockResolvedValue(CAMPAIGN_HUNTED);
    mount();
    await screen.findByTestId('campaign-header');
    const f = fold('Leads and hunts');
    expect(f).toHaveAttribute('data-testid', 'fold-leads-hunts');
    expect(f).toHaveAttribute('data-open', 'false');
    expect(fold('Findings').compareDocumentPosition(f) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(f.compareDocumentPosition(fold('Machines')) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    // Two leads of the campaign and three hunts. The related lead counts in its own fold.
    expect(within(f).getByTestId('fold-leads-hunts-detail')).toHaveTextContent('2 leads, 3 hunts');
    const body = openFold('Leads and hunts');
    // The chart of the hunts leads the fold. The two lists follow it.
    const chart = within(body).getByTestId('campaign-hunt-marks');
    expect(chart.compareDocumentPosition(within(body).getByTestId('campaign-leads')) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(body).getAllByTestId('hunt-mark')).toHaveLength(3);
  });

  it('lists a related lead under "Related, not proven" with the link to the lead', async () => {
    vi.mocked(getCampaign).mockResolvedValue(CAMPAIGN_HUNTED);
    mount();
    await screen.findByTestId('campaign-header');
    // One investigation that needs more info, one session, one named host and one related lead.
    expect(within(fold('Related, not proven')).getByTestId('fold-related-count')).toHaveTextContent('4');
    const row = within(openFold('Related, not proven')).getByTestId('related-lead-14');
    expect(row).toHaveTextContent('Lead 14: web-1 talks to a rare external address');
    expect(row).toHaveTextContent('This lead keeps normal handling.');
    expect(within(row).getByRole('link', { name: 'Open the lead' })).toHaveAttribute('href', '/leads/14');
    // NEGATIVE CONTROL: a lead of the campaign is no related candidate.
    expect(screen.queryByTestId('related-lead-12')).toBeNull();
  });

  it('keeps the related fold for a related lead alone', async () => {
    vi.mocked(getCampaign).mockResolvedValue({
      ...CAMPAIGN_HUNTED,
      related: { needsMoreInfo: [], sessions: [], named: [], falsePositiveFromTargets: 0 },
      hunts: [],
      leads: CAMPAIGN_HUNTED.leads?.filter((l) => l.related),
    });
    mount();
    await screen.findByTestId('campaign-header');
    expect(within(fold('Related, not proven')).getByTestId('fold-related-count')).toHaveTextContent('1');
    // No lead of the campaign and no hunt: the fold of the leads and the hunts does not render.
    expect(screen.queryByTestId('fold-leads-hunts')).toBeNull();
    expect(screen.queryByTestId('related-empty')).toBeNull();
  });

  it('renders no fold of the leads and the hunts for a server that sends neither', async () => {
    mount();
    await screen.findByTestId('campaign-header');
    expect(screen.queryByTestId('fold-leads-hunts')).toBeNull();
    // NEGATIVE CONTROL: the other folds stay.
    expect(fold('Findings')).toBeInTheDocument();
  });

  it('says no "run" and no "member" anywhere on the page', async () => {
    vi.mocked(getCampaign).mockResolvedValue({ ...CAMPAIGN, leads: CAMPAIGN_HUNTED.leads, hunts: CAMPAIGN_HUNTED.hunts });
    mount();
    await screen.findByTestId('campaign-header');
    // Open every fold, and show the tooltip of an arrow, of a machine and of a mark.
    for (const button of screen.getAllByRole('button', { name: /^Expand / })) fireEvent.click(button);
    const texts: string[] = [];
    const take = () => {
      texts.push(document.body.textContent ?? '');
      for (const el of document.body.querySelectorAll('[aria-label], [title]')) {
        texts.push(el.getAttribute('aria-label') ?? '', el.getAttribute('title') ?? '');
      }
    };
    take();
    const arrow = screen.getByRole('button', { name: 'actor-a to web-1: 47 alerts.' });
    fireEvent.focus(arrow);
    take();
    fireEvent.blur(arrow);
    fireEvent.focus(screen.getByRole('button', { name: 'web-1: show its alerts' }));
    take();
    for (const mark of screen.getAllByTestId('timeline-mark')) {
      fireEvent.focus(within(mark).getByRole('button'));
      take();
    }
    for (const mark of screen.getAllByTestId('hunt-mark')) {
      fireEvent.focus(within(mark).getByRole('button'));
      take();
    }
    const all = texts.join('\n');
    // The scan reads the page: it holds the folds and the tooltips.
    expect(all).toContain('soc-ai proved: Action on the target');
    expect(all).toContain('This investigation is the first confirmed attack. It started the campaign.');
    expect(all).toContain('Lead of this campaign');
    expect(all).toContain('2 findings, 1 threat finding');
    const banned = /\b(run|runs|member|members)\b/gi;
    expect(all.match(banned)).toBeNull();
    // NEGATIVE CONTROL: the pattern finds the old words, and it leaves a longer word alone.
    expect('4 runs. View proof run. Member runs.'.match(banned)).toEqual(['runs', 'run', 'Member', 'runs']);
    expect('Runbooks rerun membership'.match(banned)).toBeNull();
  });

  it('answers an unknown id as not found, with no Retry', async () => {
    vi.mocked(getCampaign).mockRejectedValue(new ApiError('campaign_not_found', 404, 'campaign_not_found'));
    mount('/campaigns/99');
    expect(await screen.findByText('No such campaign')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
    expect(screen.getByRole('link', { name: /Back to campaigns/ })).toHaveAttribute('href', '/campaigns');
  });

  it('answers a non-integer id as not found and sends no request', async () => {
    mount('/campaigns/01BOGUS');
    expect(await screen.findByText('No such campaign')).toBeInTheDocument();
    expect(getCampaign).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
  });

  // NEGATIVE CONTROL: an outage is no 404. It keeps the error card and its Retry.
  it('keeps the error card and its Retry for another failure', async () => {
    vi.mocked(getCampaign).mockRejectedValueOnce(new ApiError('boom', 500));
    mount();
    expect(await screen.findByText('Could not load this campaign')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByTestId('campaign-header')).toBeInTheDocument();
  });

  it('shows the stale notice over the sections when the rebuild failed', async () => {
    vi.mocked(getCampaign).mockResolvedValue({ ...CAMPAIGN, stale: true });
    mount();
    await screen.findByTestId('campaign-header');
    const notice = screen.getByRole('status');
    expect(notice).toHaveTextContent('This data is from');
    expect(notice).toHaveTextContent('soc-ai retries automatically.');
    expect(notice.compareDocumentPosition(screen.getByTestId('campaign-header')) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('puts the decision bar first under the title and shows the answer of Open again', async () => {
    vi.mocked(getCampaign).mockResolvedValue(CAMPAIGN_CLOSED);
    vi.mocked(reopenCampaign).mockResolvedValue(CAMPAIGN_WAITS);
    mount();
    const bar = await screen.findByTestId('campaign-decision');
    expect(bar).toHaveAttribute('data-state', 'closed');
    // Nothing of the header sits between the title row and the bar.
    const titleRow = screen.getByRole('heading', { name: 'actor-a against web-1' }).parentElement as HTMLElement;
    expect(titleRow.nextElementSibling).toBe(bar);
    fireEvent.click(within(bar).getByRole('button', { name: 'Open again' }));
    fireEvent.click(within(screen.getByTestId('campaign-reopen-confirm')).getByRole('button', { name: 'Open again' }));
    expect(await screen.findByText('This campaign waits on your decision since 2026-10-24 00:40 UTC.')).toBeInTheDocument();
    expect(screen.getByTestId('campaign-decision')).toHaveAttribute('data-state', 'waits');
  });

  it('closes the campaign from the dialog and shows the closed bar', async () => {
    vi.mocked(getCampaign).mockResolvedValue(CAMPAIGN_WAITS);
    vi.mocked(getCampaignCloseScope).mockResolvedValue({ alerts: 1083, rules: 7, capped: false });
    vi.mocked(closeCampaign).mockResolvedValue(CAMPAIGN_CLOSED);
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Close with a reason' }));
    const dialog = screen.getByRole('dialog', { name: 'Close the campaign' });
    await within(dialog).findByRole('checkbox');
    fireEvent.click(within(dialog).getByRole('radio', { name: 'Test that is over' }));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close the campaign' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(screen.getByTestId('campaign-decision')).toHaveAttribute('data-state', 'closed');
    expect(closeCampaign).toHaveBeenCalledWith(7, { reason: 'test_over', note: '', acknowledge: true });
  });

  it('opens one case from the dialog and shows the case bar', async () => {
    vi.mocked(getCampaign).mockResolvedValue(CAMPAIGN_CASE_READY);
    vi.mocked(getCampaignCaseScope).mockResolvedValue({
      title: 'soc-ai campaign: actor-a against web-1',
      alerts: 21,
      capped: false,
      skipped: { acknowledged: 3, escalated: 0, noAlert: 28 },
      existing: null,
    });
    vi.mocked(openCampaignCase).mockResolvedValue(CAMPAIGN_CASE);
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Open one case' }));
    const dialog = screen.getByRole('dialog', { name: 'Open one case' });
    await within(dialog).findByTestId('case-alerts');
    fireEvent.click(within(within(dialog).getByTestId('case-actions')).getByRole('button', { name: 'Open one case' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(screen.getByTestId('campaign-decision')).toHaveAttribute('data-state', 'case');
    expect(openCampaignCase).toHaveBeenCalledWith(7, { note: '' });
  });

  it('lists the changes of the campaign in a fold, and has no fold with no changes', async () => {
    vi.mocked(getCampaign).mockResolvedValue(CAMPAIGN_CLOSED);
    const { unmount } = mount();
    await screen.findByTestId('campaign-header');
    expect(screen.getByTestId('fold-changes-count')).toHaveTextContent(String(CAMPAIGN_CLOSED.changes?.length));
    const changes = openFold('Changes');
    expect(within(changes).getAllByTestId('campaign-change')).toHaveLength(CAMPAIGN_CLOSED.changes?.length ?? 0);
    expect(screen.getAllByTestId('timeline-decision')).toHaveLength(3);
    unmount();
    vi.mocked(getCampaign).mockResolvedValue(CAMPAIGN);
    mount();
    await screen.findByTestId('campaign-header');
    expect(screen.queryByTestId('fold-changes')).toBeNull();
  });
});
