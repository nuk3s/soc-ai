// How this flows: the chart behind every definition line.
//
// The owner asked for the flow to be visible from the page that holds it. The
// drawer renders the chart and prints one definition for each box under it, so
// a reader who cannot see the picture still gets the words. These tests pin the
// chart, its words, its alt text, the definition lines and the close.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

import chartSvg from '../assets/hunting-flow.svg?raw';
import {
  DEFINE_CAMPAIGN,
  DEFINE_CAMPAIGN_DECISION,
  DEFINE_NEEDS_YOU,
  DEFINE_SCHEDULE,
} from '../lib/tooltips';
import { ShellProvider } from '../shell/ShellContext';
import { FLOW_ALT, FLOW_SENTENCES, FlowLink, HowThisFlowsDrawer } from './HowThisFlows';

/** The words of the chart, as a reader sees them: the text of each text
 *  element, joined. */
const chartWords = [...chartSvg.matchAll(/<text[^>]*>([^<]*)<\/text>/g)]
  .map((m) => m[1].replace(/&amp;/g, '&'))
  .join(' ');

/** The words the chart and its lines never use. An investigation is no "run"
 *  and no "member", the network is no "estate", the user-facing word is
 *  "type", and the console has no "Agree" control. */
const BANNED = /\b(runs?|members?|estates?|kinds?|agree)\b/i;

const mount = (onClose = () => {}) =>
  render(
    <MemoryRouter>
      <ShellProvider>
        <HowThisFlowsDrawer open onClose={onClose} />
      </ShellProvider>
    </MemoryRouter>,
  );

describe('HowThisFlowsDrawer', () => {
  it('names itself and renders the chart at the full width of the drawer', async () => {
    mount();
    // The drawer and the link read one name for one thing.
    expect(await screen.findByText('How this flows')).toBeTruthy();
    const chart = screen.getByTestId('hunting-flow-chart');
    expect(chart.getAttribute('src')).toMatch(/hunting-flow\.svg/);
    expect(chart.style.maxWidth).toBe('100%');
  });

  it('describes the chart for a reader who cannot see it', async () => {
    mount();
    const chart = await screen.findByTestId('hunting-flow-chart');
    const alt = chart.getAttribute('alt') ?? '';
    for (const word of ['analytic', 'hit', 'lead', 'hunt', 'investigation', 'verdict', 'campaign', 'Needs you']) {
      expect(alt).toContain(word);
    }
  });

  it('prints each definition line under the chart, one item each, in the order of the chart', async () => {
    mount();
    const list = await screen.findByTestId('flow-definitions');
    const items = [...list.querySelectorAll('li')].map((li) => li.textContent);
    expect(items).toEqual([...FLOW_SENTENCES]);
    expect(items).toContain(DEFINE_CAMPAIGN);
    expect(items).toContain(DEFINE_NEEDS_YOU);
    // The schedule has its own line on the Hunts page. The chart has no box for it.
    expect(items).not.toContain(DEFINE_SCHEDULE);
  });

  it('draws the campaign and Needs you, and uses no banned word', () => {
    expect(chartWords).toContain('Campaign');
    expect(chartWords).toContain('Needs you');
    expect(chartWords).toContain('Your decision on a campaign');
    // The three decisions on a campaign, the case first (part C, 2026-11-16).
    expect(chartWords).toContain('Open one case: one Security Onion');
    expect(chartWords).toContain('Authorize:');
    expect(chartWords).toContain('Close with a reason:');
    expect(DEFINE_CAMPAIGN_DECISION).toContain('one Security Onion case for the whole campaign');
    for (const text of [chartWords, FLOW_ALT, ...FLOW_SENTENCES]) {
      expect(text).not.toMatch(BANNED);
    }
  });

  it('names no control that the console does not have', () => {
    // Negative control: the chart of 2026-10-07 offered "agree or override the
    // verdict". The console has Override and no Agree.
    expect(BANNED.test('agree or override the verdict')).toBe(true);
    expect(BANNED.test('the investigation run')).toBe(true);
    expect(chartWords).not.toMatch(/promot/i);
  });

  it('is wider than a detail drawer, because the chart is 1600 px', async () => {
    mount();
    const panel = await screen.findByRole('dialog');
    expect(panel.className).toContain('w-[1480px]');
  });

  it('closes on the Close button', async () => {
    const onClose = vi.fn();
    mount(onClose);
    fireEvent.click(await screen.findByRole('button', { name: 'Close' }));
    expect(onClose).toHaveBeenCalled();
  });
});

describe('FlowLink', () => {
  it('keeps the address of the page it is on and adds the parameter', () => {
    render(
      <MemoryRouter initialEntries={['/hunts?hits=unread']}>
        <FlowLink />
      </MemoryRouter>,
    );
    expect(screen.getByRole('link', { name: 'How this flows' }).getAttribute('href')).toBe(
      '/hunts?hits=unread&flow=1',
    );
  });

  it('sends a reader on another page to the Hunt Console', () => {
    render(
      <MemoryRouter initialEntries={['/leads/12']}>
        <FlowLink />
      </MemoryRouter>,
    );
    expect(screen.getByRole('link', { name: 'How this flows' }).getAttribute('href')).toBe(
      '/hunts?flow=1',
    );
  });
});
