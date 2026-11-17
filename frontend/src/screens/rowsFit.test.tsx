// M1 (prod review 2026-11-12, ui-core 11 and 12). At a 1100 px window the
// Alerts and Investigations rows were 998 px wide inside an 866 px card. The
// row actions sat off the right edge and a rule name wrapped to six lines.
// Under 1280 px a row now folds its low-value columns (Owner, Tags) into the
// detection cell, keeps the actions in its last column, and shows the whole
// name, wrapped. A cut text shows whole and wraps (owner, 2026-10-07).
// happy-dom draws no layout, so these tests read the grid the rows declare:
// the column floors, the gaps and the padding must fit the card, and the
// actions must sit in a declared column.
//
// Three Alerts defects are fixed with them: "· inherited 5d ago" printed over
// the confidence, "1 true positive, 1 fa/lse positive" broke inside a word, and
// the event rows swapped the colours of the source and the destination (the
// last one is pinned in components/FlowBadge.test.tsx).
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ShellProvider } from '../shell/ShellContext';
import type { AlertGroup, InvestigationList, InvestigationRow } from '../lib/types';

const listInvestigations = vi.hoisted(() => vi.fn());
const listSavedViews = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn(),
  getMe: vi.fn().mockResolvedValue({ username: 'me', role: 'analyst', status: '' }),
  listInvestigations,
  listSavedViews,
}));

import { getAlerts } from '../lib/api';
import { queueOf } from '../test/alertQueue';
import { Alerts } from './Alerts';
import { Investigations } from './Investigations';

/** The card that holds a list at a 1100 px window, measured on the console. */
const CARD_AT_1100 = 866;

/** A window narrower than 1280 px, or a wide one. */
function windowIs(wide: boolean) {
  return vi.spyOn(window, 'matchMedia').mockImplementation(
    (query: string) =>
      ({
        matches: query.includes('min-width: 1280px') ? wide : true,
        media: query,
        onchange: null,
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
        addListener: () => undefined,
        removeListener: () => undefined,
        dispatchEvent: () => false,
      }) as MediaQueryList,
  );
}

/** The floor of each column of a grid template, in px. */
function floors(template: string): number[] {
  return Array.from(template.matchAll(/minmax\((\d+)px,[^)]*\)|(\d+)px/g), (m) => Number(m[1] ?? m[2]));
}

/** The grid cells of a row: its children, less the decorative bars. */
const cells = (row: HTMLElement) =>
  Array.from(row.children).filter((c) => c.getAttribute('aria-hidden') !== 'true') as HTMLElement[];

/** The narrowest the row can be: the floors, the gaps and the padding. */
const needs = (row: HTMLElement, gap: number, padding: number) => {
  const f = floors(row.style.gridTemplateColumns);
  return f.reduce((a, b) => a + b, 0) + gap * (f.length - 1) + padding;
};

const LONG = 'ET EXPLOIT PHP php2shell Chunked Multipart Request without Content-Length (CVE-2026-109618)';

const group = (o: Partial<AlertGroup> = {}): AlertGroup => ({
  id: 'g1',
  name: LONG,
  kind: 'suricata',
  sev: 'medium',
  count: 306,
  verdict: 'true_positive',
  conf: 0.75,
  latest: '1d',
  inherited: false,
  events: [],
  owner: 'me',
  state: 'owned',
  invId: 'INV-1',
  src: '10.20.30.5',
  dst: '10.40.50.7',
  ...o,
});

const mountAlerts = (groups: AlertGroup[]) => {
  vi.mocked(getAlerts).mockResolvedValue(queueOf(groups));
  return render(
    <MemoryRouter initialEntries={['/alerts?range=24h&hide_acked=false']}>
      <ShellProvider>
        <Alerts />
      </ShellProvider>
    </MemoryRouter>,
  );
};

let media: ReturnType<typeof windowIs> | null = null;
afterEach(() => {
  media?.mockRestore();
  media = null;
});

describe('the Alerts row at 1100 px', () => {
  it('fits the card, folds Owner and Tags, and keeps the actions in the row', async () => {
    media = windowIs(false);
    mountAlerts([group()]);
    const row = await screen.findByTestId('alert-row-g1');

    // The row declares a width the card holds, and the declared width covers
    // the floors, so no column spills out of it.
    const minWidth = Number.parseInt(row.style.minWidth, 10);
    expect(minWidth).toBeLessThanOrEqual(CARD_AT_1100);
    expect(minWidth).toBeGreaterThanOrEqual(needs(row, 8, 28));

    // One declared column for each cell, and the actions in the last one.
    const columns = floors(row.style.gridTemplateColumns);
    const rowCells = cells(row);
    expect(rowCells).toHaveLength(columns.length);
    const actions = rowCells[rowCells.length - 1];
    expect(within(actions).getByRole('button', { name: 'Open investigation' })).toBeTruthy();
    expect(within(actions).getByRole('button', { name: 'Mark done' })).toBeTruthy();

    // Owner and Tags fold into the detection cell.
    const title = within(row).getByTestId('alert-title-cell');
    const folded = within(title).getByTestId('alert-folded');
    expect(within(folded).getByRole('button', { name: `Release ${LONG}` })).toBeTruthy();
    expect(within(folded).getByTestId('alert-tags-g1')).toBeTruthy();
    expect(folded.textContent).toContain('×306');
    expect(screen.queryByTestId('tags-header')).toBeNull();
    expect(screen.queryByText('Owner')).toBeNull();

    // The whole name shows and wraps: no clip and no ellipsis.
    const name = within(row).getByTestId('alert-name-box');
    expect(within(name).getByTestId('alert-name').textContent).toBe(LONG);
    expect(name.className).toContain('break-words');
    expect(name.className).not.toMatch(/max-h-|overflow-hidden|\btruncate\b|line-clamp/);
  });

  it('keeps every column at a wide window', async () => {
    // NEGATIVE CONTROL. The fold is for a narrow window only.
    media = windowIs(true);
    mountAlerts([group()]);
    const row = await screen.findByTestId('alert-row-g1');
    expect(cells(row)).toHaveLength(floors(row.style.gridTemplateColumns).length);
    expect(Number.parseInt(row.style.minWidth, 10)).toBeGreaterThanOrEqual(needs(row, 8, 28));
    expect(screen.getByTestId('tags-header')).toBeTruthy();
    expect(screen.getByText('Owner')).toBeTruthy();
    expect(within(row).queryByTestId('alert-folded')).toBeNull();
    const name = within(row).getByTestId('alert-name-box');
    expect(name.className).not.toContain('max-h-');
  });
});

// The polish review (2026-11-13): at a 1440 px window the detection column
// was 344 px beside a blank band in Tags and the actions. The card at 1440 px
// is 1182 px wide with the sidebar open. Chromium sets a rule name of 60
// characters in 409 px at 13.5 px, and the chevron takes 22 px more.
const CARD_AT_1440 = 1182;
const NAME_60 = 431;

/** The width the one `fr` track gets in a card: the card less the fixed
 *  columns, the gaps and the padding. */
const frWidth = (template: string, card: number, gap: number) => {
  const tracks = template.split(/\s+(?![^(]*\))/);
  const fixed = tracks.filter((t) => !t.includes('fr')).reduce((a, t) => a + Number.parseInt(t, 10), 0);
  expect(tracks.filter((t) => t.includes('fr'))).toHaveLength(1);
  return card - 2 - 28 - fixed - gap * (tracks.length - 1);
};

describe('the wide rows at 1440 px', () => {
  it('give the Alerts detection column the free width', async () => {
    media = windowIs(true);
    mountAlerts([group()]);
    const row = await screen.findByTestId('alert-row-g1');
    const template = row.style.gridTemplateColumns;
    // The detection column is the one track that grows.
    expect(template.split(/\s+(?![^(]*\))/)[1]).toMatch(/^minmax\(\d+px, ?1fr\)$/);
    expect(frWidth(template, CARD_AT_1440, 8)).toBeGreaterThanOrEqual(NAME_60);
    // The header declares the same columns.
    const header = screen.getByTestId('tags-header').parentElement as HTMLElement;
    expect(header.style.gridTemplateColumns).toBe(template);
    // The line may break between the name and its count, so a name that
    // fits its line never wraps a word to keep the count beside it.
    const name = within(row).getByTestId('alert-name');
    expect(name.nextSibling?.textContent).toBe(' ');
    expect(name.parentElement?.textContent).toBe(`${LONG} ×306`);
  });

  it('give the Investigations detection column the free width and the flow', async () => {
    listInvestigations.mockReset().mockResolvedValue(list([inv()]));
    listSavedViews.mockReset().mockResolvedValue([]);
    media = windowIs(true);
    mountInvestigations();
    const flow = await screen.findByTestId('inv-flow-INV-X');
    // The flow sits under the name in the detection cell.
    expect(screen.getByTestId('inv-title-cell-INV-X').contains(flow)).toBe(true);
    let row: HTMLElement | null = flow;
    while (row && !row.style.gridTemplateColumns) row = row.parentElement;
    const template = (row as HTMLElement).style.gridTemplateColumns;
    expect(template.split(/\s+(?![^(]*\))/)[1]).toMatch(/^minmax\(\d+px, ?1fr\)$/);
    // 13 px Investigations names are narrower than 13.5 px Alerts names, and
    // the widest flow on the demo data is 467 px.
    expect(frWidth(template, CARD_AT_1440, 10)).toBeGreaterThanOrEqual(467);
    expect(screen.getByRole('button', { name: 'Sort by Source → Dest' })).toBeTruthy();
  });

  it('control: a narrow row keeps the flow in its own column', async () => {
    listInvestigations.mockReset().mockResolvedValue(list([inv()]));
    listSavedViews.mockReset().mockResolvedValue([]);
    media = windowIs(false);
    mountInvestigations();
    await screen.findByTestId('inv-name-INV-X');
    expect(screen.queryByTestId('inv-flow-INV-X')).toBeNull();
    expect(screen.getByRole('button', { name: 'Sort by Source → Dest' })).toBeTruthy();
  });
});

describe('the Alerts verdict cell', () => {
  it('stacks "inherited" under the chip, so it does not print over the confidence', async () => {
    mountAlerts([
      group({
        verdict: 'false_positive',
        inherited: true,
        inheritedReason: 'Inherited from the same detection, investigated 5d ago.',
        windowVerdict: null,
        verdictAt: new Date(Date.now() - 5 * 86_400_000).toISOString(),
      }),
    ]);
    const pill = await screen.findByTestId('inherited-pill');
    expect(pill.textContent).toContain('· inherited 5d ago');
    expect(pill.className).toContain('flex-col');
  });

  it('breaks the verdict counts between words only', async () => {
    mountAlerts([
      group({
        verdict: 'false_positive',
        windowVerdict: 'true_positive',
        windowInvId: 'INV-2',
        windowConf: 0.7,
        verdictCounts: { true_positive: 1, false_positive: 1 },
      }),
    ]);
    const line = await screen.findByTestId('verdict-mix-line');
    expect(line.textContent).toBe('1 true positive, 1 false positive');
    expect(line.className).toContain('break-words');
    expect(line.className).not.toContain('break-all');
  });
});

const inv = (over: Partial<InvestigationRow> = {}): InvestigationRow => ({
  id: 'INV-X',
  name: LONG,
  kind: 'suricata',
  verdict: 'true_positive',
  conf: 0.75,
  host: '10.20.30.5',
  dst: '10.40.50.7',
  status: 'complete',
  when: '1d ago',
  ts: '2026-11-12T01:00:00+00:00',
  alertId: 'ev-1',
  isPrimary: true,
  fallback: false,
  ...over,
});

const list = (rows: InvestigationRow[]): InvestigationList => ({
  rows,
  total: rows.length,
  running: 0,
  truePositives: rows.length,
  totalAll: rows.length,
  active: false,
  limit: 50,
  offset: 0,
});

const mountInvestigations = () =>
  render(
    <MemoryRouter initialEntries={['/investigations']}>
      <Investigations />
    </MemoryRouter>,
  );

describe('the Investigations row at 1100 px', () => {
  beforeEach(() => {
    listInvestigations.mockReset().mockResolvedValue(list([inv()]));
    listSavedViews.mockReset().mockResolvedValue([]);
  });

  /** The grid row that holds the name link. */
  const rowOf = async (id: string) => {
    const name = await screen.findByTestId(`inv-name-${id}`);
    let el: HTMLElement | null = name;
    while (el && !el.style.gridTemplateColumns) el = el.parentElement;
    return el as HTMLElement;
  };

  it('fits the card, folds the Tags and keeps the delete control in the row', async () => {
    media = windowIs(false);
    mountInvestigations();
    const row = await rowOf('INV-X');
    const minWidth = Number.parseInt(row.style.minWidth, 10);
    expect(minWidth).toBeLessThanOrEqual(CARD_AT_1100);
    expect(minWidth).toBeGreaterThanOrEqual(needs(row, 10, 28));
    const rowCells = cells(row);
    expect(rowCells).toHaveLength(floors(row.style.gridTemplateColumns).length);
    expect(within(rowCells[rowCells.length - 1]).getByTitle('Delete investigation')).toBeTruthy();
    // The tags sit under the name.
    expect(within(screen.getByTestId('inv-folded-INV-X')).getByTestId('inv-tags-INV-X')).toBeTruthy();
    expect(screen.queryByTestId('tags-header')).toBeNull();
    const name = screen.getByTestId('inv-name-INV-X');
    expect(name.textContent).toBe(LONG);
    expect(name.className).not.toMatch(/max-h-|overflow-hidden/);
  });

  it('prints the headline of the run as one quiet line under the name', async () => {
    // The first line repeated the verdict chip and the Source → Dest cells
    // (polish review 2026-11-13). The row states the headline of the run.
    const headline = 'The upload request carries a web shell and the server answered 200.';
    listInvestigations.mockResolvedValue(
      list([
        inv({
          headline,
          firstLine: 'True positive. Impact: not stated. devbox 10.40.50.7 to mainsrv (server) 10.20.30.5.',
        }),
      ]),
    );
    media = windowIs(false);
    mountInvestigations();
    const row = await rowOf('INV-X');
    const line = within(row).getByTestId('inv-headline-INV-X');
    expect(line.textContent).toBe(headline);
    // The whole sentence shows and wraps: no clip.
    expect(line.className).not.toMatch(/max-h-|overflow-hidden/);
    expect(line.className).toContain('text-faint');
    // NEGATIVE CONTROL: the first line does not print.
    expect(row.textContent).not.toContain('Impact: not stated');
    // The row still fits the card.
    expect(Number.parseInt(row.style.minWidth, 10)).toBeLessThanOrEqual(CARD_AT_1100);
    expect(cells(row)).toHaveLength(floors(row.style.gridTemplateColumns).length);
  });

  it('control: a row with no headline prints no line under the name', async () => {
    listInvestigations.mockResolvedValue(list([inv({ headline: null }), inv({ id: 'INV-Y', alertId: 'ev-2', headline: '  ' })]));
    media = windowIs(false);
    mountInvestigations();
    await rowOf('INV-X');
    await rowOf('INV-Y');
    expect(screen.queryByTestId('inv-headline-INV-X')).toBeNull();
    expect(screen.queryByTestId('inv-headline-INV-Y')).toBeNull();
  });

  it('shows the impact chip beside the verdict only when the row states one', async () => {
    listInvestigations.mockResolvedValue(
      list([
        inv({ id: 'INV-S', alertId: 'ev-s', impact: 'succeeded' }),
        inv({ id: 'INV-A', alertId: 'ev-a', impact: 'attempted' }),
        inv({ id: 'INV-N', alertId: 'ev-n', impact: 'none' }),
        inv({ id: 'INV-U', alertId: 'ev-u', impact: 'unknown' }),
        inv({ id: 'INV-M', alertId: 'ev-m', impact: null }),
      ]),
    );
    media = windowIs(true);
    mountInvestigations();
    const chipOf = async (id: string) =>
      within(await rowOf(id)).queryByTestId('impact-chip')?.getAttribute('data-impact') ?? null;
    expect(await chipOf('INV-S')).toBe('succeeded');
    expect(await chipOf('INV-A')).toBe('attempted');
    expect(await chipOf('INV-N')).toBe('none');
    // NEGATIVE CONTROL: an unknown or a missing impact shows no chip.
    expect(await chipOf('INV-U')).toBeNull();
    expect(await chipOf('INV-M')).toBeNull();
  });

  it('keeps the waiting actions inside the card', async () => {
    listInvestigations.mockResolvedValue(
      list([
        inv({
          pendingActions: 1,
          waitingActions: [
            {
              index: 0,
              tool: 'escalate_to_case',
              label: 'Escalate to case',
              target: 'alert',
              rationale: 'The payload matches the exploit.',
              executable: true,
              reason: null,
            },
          ] as unknown as InvestigationRow['waitingActions'],
        }),
      ]),
    );
    media = windowIs(false);
    mountInvestigations();
    const actions = await screen.findByTestId('waiting-actions-INV-X');
    const band = actions.parentElement as HTMLElement;
    expect(Number.parseInt(band.style.minWidth, 10)).toBeLessThanOrEqual(CARD_AT_1100);
  });

  it('keeps the Tags column at a wide window', async () => {
    // NEGATIVE CONTROL.
    media = windowIs(true);
    mountInvestigations();
    const row = await rowOf('INV-X');
    expect(screen.getByTestId('tags-header')).toBeTruthy();
    expect(screen.queryByTestId('inv-folded-INV-X')).toBeNull();
    expect(cells(row)).toHaveLength(floors(row.style.gridTemplateColumns).length);
    expect(Number.parseInt(row.style.minWidth, 10)).toBeGreaterThanOrEqual(needs(row, 10, 28));
    expect(screen.getByTestId('inv-name-INV-X').className).not.toContain('max-h-');
  });
});
