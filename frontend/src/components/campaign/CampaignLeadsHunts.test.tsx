import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import type { CampaignChange, CampaignHunt } from '../../lib/api';
import { STAGE_COLOR } from '../../lib/campaignViz';
import { forbiddenWords } from '../../test/analystWords';
import { CAMPAIGN_HUNTED, CAMPAIGN_HUNTS, CAMPAIGN_LEADS } from '../../test/campaign';
import { CampaignLeadsHunts } from './CampaignLeadsHunts';

function mount(over: { hunts?: CampaignHunt[]; changes?: CampaignChange[] } = {}) {
  return render(
    <MemoryRouter initialEntries={['/campaigns/7']}>
      <Routes>
        <Route
          path="/campaigns/7"
          element={
            <CampaignLeadsHunts
              leads={CAMPAIGN_LEADS}
              hunts={over.hunts ?? CAMPAIGN_HUNTS}
              changes={over.changes ?? CAMPAIGN_HUNTED.changes ?? []}
              firstEvent={CAMPAIGN_HUNTED.firstEvent}
              lastEvent={CAMPAIGN_HUNTED.lastEvent}
            />
          }
        />
        <Route path="/hunts/:id" element={<div data-testid="hunt-page" />} />
      </Routes>
    </MemoryRouter>,
  );
}

const x = (el: Element) => Number(el.getAttribute('data-x'));

describe('CampaignLeadsHunts', () => {
  it('draws one mark for each hunt on the time axis, oldest at the left, in the neutral tone', () => {
    mount();
    const chart = screen.getByTestId('campaign-hunt-marks');
    const marks = within(chart).getAllByTestId('hunt-mark');
    expect(marks.map((m) => m.getAttribute('data-hunts'))).toEqual(['hunt-seed', 'hunt-schedule', 'hunt-stage']);
    expect(x(marks[0])).toBeLessThan(x(marks[1]));
    expect(x(marks[1])).toBeLessThan(x(marks[2]));
    // The hunts add no color: each mark wears the neutral tone.
    for (const m of marks) expect(m.querySelector('rect')?.getAttribute('fill')).toBe('rgb(var(--text-2))');
    // The axis states its times.
    expect(within(chart).getAllByTestId('hunt-axis-tick').length).toBeGreaterThan(1);
    expect(chart).toHaveTextContent('Hunts');
    expect(chart).toHaveTextContent('Changes');
  });

  it('states the findings of a hunt in the hover, and opens the hunt on a click', () => {
    mount();
    const mark = screen.getAllByTestId('hunt-mark')[2];
    const target = within(mark).getByRole('button');
    expect(target).toHaveAccessibleName(
      'Campaign hunt, 2026-10-28 22:52 UTC: 2 findings, 1 threat finding. Complete.',
    );
    fireEvent.focus(target);
    const tip = screen.getByTestId('hunt-mark-tooltip');
    expect(tip).toHaveTextContent('Campaign hunt');
    expect(tip).toHaveTextContent('2026-10-28 22:52 UTC');
    expect(tip).toHaveTextContent('2 findings, 1 threat finding');
    // The tooltip draws on the document body, so no panel cuts it.
    expect(tip.parentElement).toBe(document.body);
    fireEvent.click(target);
    expect(screen.getByTestId('hunt-page')).toBeInTheDocument();
  });

  it('marks each change beside the hunts, and fills the changes that can start a hunt', () => {
    mount({
      changes: [
        ...(CAMPAIGN_HUNTED.changes ?? []),
        { id: 9, type: 'decided', at: '2026-10-29T10:00:00Z', detail: { decision: 'closed', by: 'admin' } },
      ],
    });
    const changes = screen.getAllByTestId('hunt-change-mark');
    // The formed change and the new machine sit five minutes apart: one mark at this scale.
    expect(changes.map((c) => c.getAttribute('data-types'))).toEqual(['formed party', 'stage', 'decided']);
    expect(changes.map((c) => c.getAttribute('data-starts'))).toEqual(['yes', 'yes', 'no']);
    // The stage change wears the color of the stage it reached.
    expect(changes[1].querySelector('rect')?.getAttribute('fill')).toBe(STAGE_COLOR.action);
    expect(changes[0].querySelector('rect')?.getAttribute('fill')).toBe('rgb(var(--text-2))');
    fireEvent.focus(within(changes[0]).getByRole('img'));
    const tip = screen.getByTestId('hunt-mark-tooltip');
    expect(tip).toHaveTextContent('soc-ai formed the campaign.');
    expect(tip).toHaveTextContent('2 new machines joined the campaign: db-1, mail-1.');
    expect(tip).not.toHaveTextContent('This change starts no hunt.');
    // NEGATIVE CONTROL: a decision starts no hunt. N11: the lane read empty
    // beside a fold that listed a close, so the decision draws a hollow mark
    // whose hover says that it starts no hunt.
    expect(changes[2].querySelector('rect')?.getAttribute('fill')).toBe('rgb(var(--surface-1))');
    fireEvent.focus(within(changes[2]).getByRole('img'));
    expect(screen.getByTestId('hunt-mark-tooltip')).toHaveTextContent('This change starts no hunt.');
  });

  it('reaches the newest change on the time axis', () => {
    // N11: two changes after the newest hunt. The axis reaches them.
    mount({
      changes: [
        ...(CAMPAIGN_HUNTED.changes ?? []),
        { id: 9, type: 'decided', at: '2026-11-15T01:01:00Z', detail: { decision: 'closed', by: 'admin' } },
      ],
    });
    const hunts = screen.getAllByTestId('hunt-mark');
    const newestHunt = Math.max(...hunts.map(x));
    const closed = screen.getAllByTestId('hunt-change-mark').find((c) => c.getAttribute('data-types') === 'decided')!;
    expect(x(closed)).toBeGreaterThan(newestHunt);
    // The mark sits on the plot, inside the width of the chart.
    const width = Number(screen.getByTestId('campaign-hunt-marks').querySelector('svg')?.getAttribute('width'));
    expect(x(closed)).toBeLessThan(width);
  });

  it('joins two hunts that sit too close to draw apart, and lists both in the hover', () => {
    mount({
      hunts: [
        { ...CAMPAIGN_HUNTS[2], id: 'hunt-b', startedAt: '2026-10-24T01:18:00Z', starter: 'analyst' },
        CAMPAIGN_HUNTS[2],
      ],
    });
    const marks = screen.getAllByTestId('hunt-mark');
    expect(marks).toHaveLength(1);
    expect(marks[0]).toHaveTextContent('2');
    fireEvent.focus(within(marks[0]).getByRole('img'));
    const tip = screen.getByTestId('hunt-mark-tooltip');
    expect(tip).toHaveTextContent('Lead hunt');
    expect(tip).toHaveTextContent('Manual hunt');
  });

  it('lists the leads of the campaign as handled by it, with one link each', () => {
    mount();
    const list = screen.getByTestId('campaign-leads');
    const rows = within(list).getAllByRole('listitem');
    expect(rows.map((r) => r.getAttribute('data-testid'))).toEqual(['campaign-lead-12', 'campaign-lead-13']);
    expect(rows[0]).toHaveTextContent('Lead of this campaign');
    expect(rows[0]).toHaveTextContent('Lead 12: actor-a on web-1');
    expect(rows[0]).toHaveTextContent('Hunted');
    expect(rows[1]).toHaveTextContent('The hunts of the campaign cover this lead.');
    expect(within(rows[1]).getByRole('link', { name: 'Open the lead' })).toHaveAttribute('href', '/leads/13');
    // A lead of the campaign does not read as work that waits.
    expect(list.textContent).not.toMatch(/waits|queued|decision/i);
    // NEGATIVE CONTROL: the related lead is in the fold "Related, not proven", not here.
    expect(within(list).queryByText(/Lead 14/)).toBeNull();
  });

  it('lists the hunts newest first with the starter, the time, the status and the findings', () => {
    mount();
    const rows = within(screen.getByTestId('campaign-hunts')).getAllByRole('listitem');
    expect(rows.map((r) => r.getAttribute('data-testid'))).toEqual([
      'campaign-hunt-hunt-stage',
      'campaign-hunt-hunt-schedule',
      'campaign-hunt-hunt-seed',
    ]);
    expect(within(rows[0]).getByRole('link', { name: 'Campaign hunt' })).toHaveAttribute('href', '/hunts/hunt-stage');
    expect(rows[0]).toHaveTextContent('2026-10-28 22:52 UTC');
    expect(rows[0]).toHaveTextContent('Complete');
    expect(rows[0]).toHaveTextContent('2 findings, 1 threat finding');
    expect(rows[1]).toHaveTextContent('Scheduled hunt');
    expect(rows[1]).toHaveTextContent('4 findings, no threat finding');
    expect(rows[2]).toHaveTextContent('Lead hunt');
    // NEGATIVE CONTROL: a list under the cap states no cap.
    expect(screen.queryByTestId('campaign-hunts-cap')).toBeNull();
  });

  it('states the cap when the server sends the 20 newest hunts', () => {
    const hunts = Array.from({ length: 20 }, (_, i) => ({
      ...CAMPAIGN_HUNTS[0],
      id: `hunt-${i}`,
      startedAt: new Date(Date.parse('2026-10-28T22:52:00Z') - i * 86_400_000).toISOString(),
    }));
    mount({ hunts });
    expect(screen.getByTestId('campaign-hunts-cap')).toHaveTextContent('The list shows the 20 newest hunts.');
  });

  it('draws no chart and no hunt list with no hunt, and keeps the leads', () => {
    mount({ hunts: [] });
    expect(screen.queryByTestId('campaign-hunt-marks')).toBeNull();
    expect(screen.queryByTestId('campaign-hunts')).toBeNull();
    const rows = within(screen.getByTestId('campaign-leads')).getAllByRole('listitem');
    // With no hunt on record, no hunt covers the lead.
    expect(rows[1]).toHaveTextContent('No hunt ran on this lead.');
    expect(rows[1]).not.toHaveTextContent('The hunts of the campaign cover this lead.');
  });

  it('says no "run", no "member" and no "kind" in the fold or its hover', () => {
    mount();
    const root = screen.getByTestId('campaign-leads-hunts');
    const found = [...forbiddenWords(root)];
    for (const mark of screen.getAllByTestId('hunt-mark')) {
      fireEvent.focus(within(mark).getByRole('button'));
      found.push(...forbiddenWords(screen.getByTestId('hunt-mark-tooltip')));
    }
    expect(found).toEqual([]);
    expect(root.textContent).not.toMatch(/\bkinds?\b/i);
  });

  // F5: the fold read "Failed" for a hunt that the lead page states as
  // "Stopped with an error after 14 steps". The fold reads the one function.
  it('states the steps of a hunt that stopped, as the hunt page does', () => {
    mount({
      hunts: [
        { id: 'hunt-stop', starter: 'lead', status: 'error', startedAt: '2026-10-28T22:52:00Z', findings: 0, threatFindings: 0, steps: 14 },
        { id: 'hunt-none', starter: 'lead', status: 'error', startedAt: '2026-10-27T22:52:00Z', findings: 0, threatFindings: 0, steps: 0 },
        ...CAMPAIGN_HUNTS,
      ],
    });
    expect(screen.getByTestId('campaign-hunt-hunt-stop')).toHaveTextContent('Stopped with an error after 14 steps');
    expect(screen.getByTestId('campaign-hunt-hunt-none')).toHaveTextContent('Could not run');
    for (const id of ['hunt-stop', 'hunt-none']) {
      expect(screen.getByTestId(`campaign-hunt-${id}`)).not.toHaveTextContent('Failed');
    }
    // Negative control: a complete hunt keeps its status word.
    expect(screen.getByTestId('campaign-hunt-hunt-stage')).toHaveTextContent('Complete');
  });
});
