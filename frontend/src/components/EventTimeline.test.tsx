// The Event timeline lists the documents of a run in event time, in UTC, with
// the waves (change D). The step timelines list tool-call order, and three
// waves of one attack read as one burst. Every time here is an offset from
// Date.now(), so no test rots with the calendar.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getEvent: vi.fn(),
}));

import { getEvent } from '../lib/api';
import type { EventTimeline, EventTimelineEntry } from '../lib/types';
import { ShellProvider } from '../shell/ShellContext';
import { EventTimelinePanel, eventTimelineMeta } from './EventTimeline';

const MIN = 60_000;
// Whole seconds, so the ISO strings carry .000Z like the server's.
const BASE = Math.floor((Date.now() - 5 * 86_400_000) / 1000) * 1000;
const iso = (ms: number) => new Date(ms).toISOString();
const utc = (ms: number) => `${new Date(ms).toISOString().slice(0, 19).replace('T', ' ')} UTC`;

function entry(over: Partial<EventTimelineEntry> & { id: string; at: string }): EventTimelineEntry {
  return {
    end: null,
    dataset: 'zeek.conn',
    source: '192.0.2.10',
    destination: '198.51.100.20:22',
    host: null,
    label: 'Connection, state SF',
    cited: true,
    findings: [],
    wave: 1,
    ...over,
  };
}

const EXPLOIT = BASE + (22 * 60 + 27) * MIN + 50 * MIN;

function timeline(over: Partial<EventTimeline> = {}): EventTimeline {
  return {
    basis: 'alert',
    gapMinutes: 30,
    untimed: 0,
    omitted: 0,
    entries: [
      entry({ id: 'docConn00000001', at: iso(BASE), end: iso(BASE + 50 * MIN), wave: 1 }),
      entry({
        id: 'docAlert0000001',
        at: iso(EXPLOIT),
        dataset: 'suricata.alert',
        source: '192.0.2.11',
        destination: '198.51.100.20',
        label: 'ET EXPLOIT Example upload attempt',
        wave: 2,
      }),
    ],
    waves: [
      {
        n: 1,
        start: iso(BASE),
        end: iso(BASE + 50 * MIN),
        documents: 1,
        sources: ['192.0.2.10'],
        destinations: ['198.51.100.20'],
      },
      {
        n: 2,
        start: iso(EXPLOIT),
        end: iso(EXPLOIT),
        documents: 1,
        sources: ['192.0.2.11'],
        destinations: ['198.51.100.20'],
      },
    ],
    ...over,
  };
}

function renderPanel(t: EventTimeline) {
  return render(
    <ShellProvider>
      <EventTimelinePanel timeline={t} />
    </ShellProvider>,
  );
}

beforeEach(() => {
  vi.mocked(getEvent).mockReset().mockResolvedValue({
    id: 'docConn00000001',
    dataset: 'zeek.conn',
    timestamp: iso(BASE),
    source: { event: { dataset: 'zeek.conn' } },
  });
});

describe('EventTimelinePanel', () => {
  it('renders the waves in order with the gap between them', () => {
    renderPanel(timeline());
    const waves = screen.getAllByTestId('event-wave');
    expect(waves).toHaveLength(2);
    expect(within(waves[0]).getByText('Wave 1')).toBeTruthy();
    expect(within(waves[1]).getByText('Wave 2')).toBeTruthy();
    expect(screen.getByText('This wave starts 22h 27m after wave 1 ends.')).toBeTruthy();
    expect(screen.getByText(/A new wave starts after a gap of more than 30 minutes/)).toBeTruthy();
    expect(screen.getByText(/the alert and the documents that the verdict cites/)).toBeTruthy();
  });

  it('shows the UTC date and time with seconds and the length of a lasting row', () => {
    renderPanel(timeline());
    const rows = screen.getAllByTestId('event-row');
    expect(within(rows[0]).getByText(utc(BASE))).toBeTruthy();
    expect(within(rows[0]).getByText('lasted 50m 0s')).toBeTruthy();
    expect(within(rows[0]).getByText('192.0.2.10 → 198.51.100.20:22')).toBeTruthy();
  });

  it('names a row with no address by its host', () => {
    const t = timeline();
    t.entries[1] = { ...t.entries[1], source: null, destination: null, host: 'web-01.example.test' };
    renderPanel(t);
    expect(screen.getByText('on web-01.example.test')).toBeTruthy();
  });

  it('shows the finding chips on a hunt', () => {
    const t = timeline({ basis: 'hunt' });
    t.entries[0] = { ...t.entries[0], findings: [0, 2] };
    renderPanel(t);
    const f1 = screen.getByText('F1');
    expect(f1.getAttribute('title')).toBe('Finding 1 cites this document.');
    expect(screen.getByText('F3').getAttribute('title')).toBe('Finding 3 cites this document.');
    expect(screen.getByText(/the documents that the findings cite/)).toBeTruthy();
  });

  it('names the finding as the source of the list on a run that judges one finding', () => {
    renderPanel(timeline({ basis: 'finding' }));
    expect(
      screen.getByText(
        /This list shows the documents that the finding cites and the documents that the verdict cites/,
      ),
    ).toBeTruthy();
    expect(screen.queryByText(/that soc-ai loaded for this investigation/)).toBeNull();
  });

  it('shows the cited chip only when some rows are not cited', () => {
    const { unmount } = renderPanel(timeline());
    expect(screen.queryByText('cited')).toBeNull();
    unmount();
    const t = timeline();
    t.entries[1] = { ...t.entries[1], cited: false };
    renderPanel(t);
    const chip = screen.getByText('cited');
    expect(chip.getAttribute('title')).toBe('The verdict cites this document.');
    expect(screen.getAllByText('cited')).toHaveLength(1);
  });

  it('states the untimed and the omitted documents in the singular and the plural', () => {
    const { unmount } = renderPanel(timeline({ untimed: 1, omitted: 1 }));
    expect(
      screen.getByText('soc-ai holds no event time for 1 cited document. It is not on this list.'),
    ).toBeTruthy();
    expect(screen.getByText('This list stops at 2 documents. 1 later document is not on it.')).toBeTruthy();
    unmount();
    renderPanel(timeline({ untimed: 3, omitted: 4 }));
    expect(
      screen.getByText('soc-ai holds no event time for 3 cited documents. They are not on this list.'),
    ).toBeTruthy();
    expect(screen.getByText('This list stops at 2 documents. 4 later documents are not on it.')).toBeTruthy();
  });

  it('shows a long label whole', () => {
    const long = `POST /wp-upload.php?${'a=1&'.repeat(80)}end=1, status 200`;
    const t = timeline();
    t.entries[1] = { ...t.entries[1], label: long };
    renderPanel(t);
    const label = screen.getByText(long);
    expect(label.textContent).toBe(long);
    expect(label.className).not.toMatch(/truncate|line-clamp/);
    expect(label.textContent).not.toContain('…');
  });

  it('opens the document from its chip', async () => {
    renderPanel(timeline());
    fireEvent.click(screen.getByRole('button', { name: 'docConn00000001' }));
    await waitFor(() => expect(getEvent).toHaveBeenCalledWith('docConn00000001'));
    expect(await screen.findByRole('dialog')).toBeTruthy();
  });
});

describe('eventTimelineMeta', () => {
  it('counts the documents and the waves and names the zone', () => {
    expect(eventTimelineMeta(timeline())).toBe('2 documents · 2 waves · UTC');
    const one = timeline();
    one.entries = [one.entries[0]];
    one.waves = [one.waves[0]];
    expect(eventTimelineMeta(one)).toBe('1 document · 1 wave · UTC');
  });
});
