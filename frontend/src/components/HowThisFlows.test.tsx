// How hunting flows — the chart behind every definition line.
//
// The owner asked for the flow to be visible from the page that runs it. The
// drawer renders the chart and repeats the five sentences under it, so a reader
// who cannot see the picture still gets the words. These tests pin the chart,
// its alt text, the five sentences and the close.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

import {
  DEFINE_ANALYTIC,
  DEFINE_HIT,
  DEFINE_HUNT,
  DEFINE_LEAD,
  DEFINE_SCHEDULE,
} from '../lib/tooltips';
import { ShellProvider } from '../shell/ShellContext';
import { FlowLink, HowThisFlowsDrawer } from './HowThisFlows';

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
    expect(await screen.findByText('How hunting flows')).toBeTruthy();
    const chart = screen.getByTestId('hunting-flow-chart');
    expect(chart.getAttribute('src')).toMatch(/hunting-flow\.svg/);
    expect(chart.style.maxWidth).toBe('100%');
  });

  it('describes the chart for a reader who cannot see it', async () => {
    mount();
    const chart = await screen.findByTestId('hunting-flow-chart');
    const alt = chart.getAttribute('alt') ?? '';
    expect(alt).toContain('analytic');
    expect(alt).toContain('hit');
    expect(alt).toContain('lead');
    expect(alt).toContain('hunt');
    expect(alt).toContain('investigation');
  });

  it('repeats the five sentences under the chart', async () => {
    mount();
    const list = await screen.findByTestId('flow-definitions');
    for (const sentence of [
      DEFINE_HIT,
      DEFINE_LEAD,
      DEFINE_HUNT,
      DEFINE_SCHEDULE,
      DEFINE_ANALYTIC,
    ]) {
      expect(list.textContent).toContain(sentence);
    }
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
