// Day-1 tier (Wave 2): the Config page used to render every setting in a
// group at once — up to 109 controls with no way to tell "decide this on day
// one" from "revisit only if something goes wrong" (dogfood 2026-08-01, the
// same overload that motivated the master-detail rebuild this file sits
// beside). `SettingSpec.day1` (server-curated, never hardcoded on the
// frontend) now splits each group into its day1 rows — rendered immediately —
// and an Advanced fold for the rest, collapsed by default and keyed
// `${g.title}:advanced` in the same `collapsed` record renderGroup already
// used for whole-section folds. Settings search still walks every item
// regardless of tier (the index is unfiltered), and a hit on a folded item
// must open BOTH its section and its fold before the highlight flash lands on
// a row that is actually in the DOM.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('./AgentToolsPanel', () => ({ AgentToolsPanel: () => null }));
vi.mock('./ApiKeysPanel', () => ({ ApiKeysPanel: () => <div data-testid="panel-api-keys" /> }));
vi.mock('./DataSourcesPanel', () => ({ DataSourcesPanel: () => null }));
vi.mock('./EgressPolicyPanel', () => ({ EgressPolicyPanel: () => null }));
vi.mock('./NotificationsPanel', () => ({ NotificationsPanel: () => null }));
vi.mock('./RedactionPreviewPanel', () => ({ RedactionPreviewPanel: () => null }));
vi.mock('./DetectionTuningPanel', () => ({ DetectionTuningPanel: () => <div data-testid="panel-detection-tuning" /> }));
vi.mock('./MaintenancePanel', () => ({ MaintenancePanel: () => null }));
vi.mock('./RunbooksPanel', () => ({ RunbooksPanel: () => null }));

// Two server-driven groups: one mixed (a day1 row + an advanced row) under
// Triage & Workflow, one ALL-advanced (zero day1 items) under Retrieval &
// Memory — the two shapes the behavior contract calls out.
const GROUPS = vi.hoisted(() => [
  {
    title: 'Triage automation',
    parent: 'Triage & Workflow',
    items: [
      {
        key: 'auto_triage_schedule_enabled',
        label: 'Continuous auto-investigate',
        help: 'Run auto-triage on a schedule.',
        source: 'db',
        apply: 'hot-apply',
        type: 'toggle',
        value: true,
        day1: true,
      },
      {
        key: 'auto_triage_inheritance_enabled',
        label: 'Verdict inheritance',
        help: 'Reuse a standing verdict within the window.',
        source: 'db',
        apply: 'hot-apply',
        type: 'toggle',
        value: true,
        day1: false,
      },
    ],
  },
  {
    title: 'Memory',
    parent: 'Retrieval & Memory',
    items: [
      {
        key: 'rag_embed_model',
        label: 'Embeddings model',
        help: 'Model used to embed runbooks.',
        source: 'db',
        apply: 'restart',
        type: 'text',
        value: '',
        day1: false,
      },
    ],
  },
]);

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getConfig: vi.fn(() => Promise.resolve({ groups: GROUPS, tokens: [], users: [], dangerHost: '' })),
  setSetting: vi.fn(() => Promise.resolve({ ok: true, restart_required: false })),
  listUsers: vi.fn().mockResolvedValue({ users: [] }),
  listDangerSettings: vi.fn().mockResolvedValue([]),
  getGatewayModels: vi.fn().mockResolvedValue({ ok: true, models: [] }),
  getInternalIdentifiers: vi.fn().mockResolvedValue({
    groups: [],
    last_scan: { running: false, last_scan: null, last_summary: null, note: null },
  }),
}));

import { Config } from './Config';

const renderAt = (entry: string | { pathname: string; hash?: string; state?: unknown }) =>
  render(
    <MemoryRouter initialEntries={[entry as never]}>
      <Config />
    </MemoryRouter>,
  );

beforeEach(() => {
  localStorage.clear();
});

describe('day1 tier: visible rows up front, the rest behind Advanced', () => {
  it('renders day1 items and folds the rest under Advanced', async () => {
    // Regression pinned: before the tier split, every setting in a group
    // rendered at once — the wall of controls the day1 curation exists to
    // fix. A non-day1 item must stay out of the DOM until its section's
    // Advanced fold is opened, and (re)appear once it is.
    renderAt({ pathname: '/config', hash: '#triage-automation' });
    expect(await screen.findByText(/auto_triage_schedule_enabled/)).toBeTruthy();
    expect(screen.queryByText(/auto_triage_inheritance_enabled/)).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: /advanced \(1\)/i }));
    expect(await screen.findByText(/auto_triage_inheritance_enabled/)).toBeTruthy();
  });

  it('a group with zero day1 items renders OPEN by default, and the toggle still folds it', async () => {
    // Regression pinned (controller-ratified product call, not just a
    // rendering nuance): the fold exists to protect a day-1 surface from
    // overload. Where a section has NO day1 items, folding everything adds a
    // click without decluttering anything — so an all-advanced section
    // defaults OPEN (advCollapsed falls back to day1Items.length > 0, not a
    // flat `true`). The section header still renders either way (the nav
    // must stay complete), and it's a REAL toggle, not a permanently-open
    // state — clicking it folds the section like any other.
    renderAt({ pathname: '/config', hash: '#memory' });
    expect((await screen.findAllByText('Memory')).length).toBeGreaterThan(0);
    expect(await screen.findByText(/rag_embed_model/)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: /advanced \(1\)/i }));
    await waitFor(() => expect(screen.queryByText(/rag_embed_model/)).toBeNull());
  });

  it('an explicitly folded all-advanced section stays folded — the stored choice wins over the smart default', async () => {
    // Regression pinned: the open-by-default above only fills in when nothing
    // is stored yet. Once the analyst has folded it, that choice persists
    // like every other key in this record — the default is a first-visit
    // convenience, not a special case that ignores `collapsed`.
    localStorage.setItem('soc-ai:config:collapsed', JSON.stringify({ 'Memory:advanced': true }));
    renderAt({ pathname: '/config', hash: '#memory' });
    expect((await screen.findAllByText('Memory')).length).toBeGreaterThan(0);
    expect(screen.queryByText(/rag_embed_model/)).toBeNull();
  });
});

describe('search finds advanced items and reveals them on click', () => {
  it('a search hit on a folded item expands BOTH the section and the fold', async () => {
    // Regression pinned: the search index already walks every item
    // regardless of tier, but a click used to expand only the SECTION
    // (navigateToSection's original behaviour). A hit on a non-day1 item
    // would then jump to the right section and set the highlight key on a
    // row that still wasn't in the DOM — a flash that lands on nothing.
    // Explicit hash rather than the default landing section: this fixture has
    // no group of its own under Models & Reasoning, so the spliced-in
    // agent-tools panel — not Triage automation — would win the default slot.
    renderAt({ pathname: '/config', hash: '#triage-automation' });
    await screen.findByText(/auto_triage_schedule_enabled/);

    const box = screen.getAllByPlaceholderText(/search settings/i)[0];
    fireEvent.change(box, { target: { value: 'inheritance' } });
    const hit = await screen.findByTestId('search-result-auto_triage_inheritance_enabled');
    expect(hit.textContent).toContain('Verdict inheritance');
    fireEvent.click(hit);

    await waitFor(() => {
      const row = document.querySelector('[data-setting-key="auto_triage_inheritance_enabled"]');
      expect(row).not.toBeNull();
      expect(row!.getAttribute('data-highlighted')).toBe('true');
    });
  });
});

describe('the apply-bar chip re-opens a folded item on click', () => {
  it('staging an advanced setting, folding it again, then clicking its chip reopens the fold', async () => {
    // Regression pinned: the apply-bar chip's click handler jumped to the
    // owning SECTION and flashed the row, but never touched the row's own
    // Advanced fold — a fold is independent of the staged edit inside it, so
    // staging a change and then folding the section again (or never having
    // unfolded a re-visited section at all) left the chip flashing a row
    // that wasn't in the DOM. The chip must reopen the fold, same as a
    // search hit on the same kind of item.
    renderAt({ pathname: '/config', hash: '#triage-automation' });
    await screen.findByText(/auto_triage_schedule_enabled/);

    // Reveal the advanced row and stage an edit on it.
    fireEvent.click(screen.getByRole('button', { name: /advanced \(1\)/i }));
    fireEvent.click(await screen.findByRole('switch', { name: 'auto_triage_inheritance_enabled' }));
    await screen.findByTestId('chip-auto_triage_inheritance_enabled');

    // Fold it back up — the staged edit (and its chip) survive independently
    // of the fold's own open/closed state.
    fireEvent.click(screen.getByRole('button', { name: /advanced \(1\)/i }));
    await waitFor(() => expect(screen.queryByText(/auto_triage_inheritance_enabled/)).toBeNull());

    fireEvent.click(screen.getByTestId('chip-auto_triage_inheritance_enabled'));
    await waitFor(() => {
      const row = document.querySelector('[data-setting-key="auto_triage_inheritance_enabled"]');
      expect(row).not.toBeNull();
      expect(row!.getAttribute('data-highlighted')).toBe('true');
    });
  });
});

describe('tier-aware fold unfolding (final-review I1/I2)', () => {
  it('a palette jump (router-state highlightKey) to an advanced item in a mixed section reveals the row', async () => {
    // Pins I1: the palette hand-off effect used to set highlightKey without
    // ever touching the section's Advanced fold, so a palette jump straight
    // to a non-day1 setting (via /config#<section>, { state: { highlightKey
    // } }) flashed nothing — the row stayed folded and out of the DOM. The
    // masterdetail fixture's palette test (Config.masterdetail.test.tsx) is
    // blind to this: both its settings are day1, so its section never has an
    // Advanced fold to miss. This fixture's Triage automation section is
    // mixed (one day1 row, one advanced row) — the shape the regression
    // actually needs.
    renderAt({
      pathname: '/config',
      hash: '#triage-automation',
      state: { highlightKey: 'auto_triage_inheritance_enabled' },
    });
    await waitFor(() => {
      const row = document.querySelector('[data-setting-key="auto_triage_inheritance_enabled"]');
      expect(row).not.toBeNull();
      expect(row!.getAttribute('data-highlighted')).toBe('true');
    });
  });

  it('jumping to a day1 item via its apply-bar chip does not unfold (or persist-unfold) the section Advanced fold', async () => {
    // Pins I2: the chip (and search-hit) click handlers used to unfold
    // `${title}:advanced` unconditionally, even for a day1 target that was
    // never folded to begin with. Since `collapsed` mirrors to localStorage,
    // that unfold PERSISTED — staging and revisiting a day1 setting (e.g.
    // analyst_model) permanently popped its section's Advanced fold open,
    // eroding the day-1 view through ordinary use. Staging the day1 row here
    // and clicking its chip must leave the fold untouched: the advanced
    // sibling stays hidden, and the collapsed record never gains the key.
    renderAt({ pathname: '/config', hash: '#triage-automation' });
    await screen.findByText(/auto_triage_schedule_enabled/);

    fireEvent.click(screen.getByRole('switch', { name: 'auto_triage_schedule_enabled' }));
    fireEvent.click(await screen.findByTestId('chip-auto_triage_schedule_enabled'));

    await waitFor(() => {
      const row = document.querySelector('[data-setting-key="auto_triage_schedule_enabled"]');
      expect(row!.getAttribute('data-highlighted')).toBe('true');
    });
    // The advanced sibling never entered the DOM...
    expect(screen.queryByText(/auto_triage_inheritance_enabled/)).toBeNull();
    // ...and the fold was never written into the persisted collapsed record.
    const stored = JSON.parse(localStorage.getItem('soc-ai:config:collapsed') || '{}');
    expect(stored['Triage automation:advanced']).toBeUndefined();
  });
});
