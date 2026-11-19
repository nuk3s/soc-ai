// The command palette finds the page of a rule decision (round 3, RC1): each
// rule with open false positives in Needs you, and each standing decision in
// force. One hit for each rule.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getNeedsYouItems, getRuleDecisions, listMachines, ruleKeyOf, searchEntityIndex } from '../lib/api';
import { CommandPalette } from './CommandPalette';
import { ShellProvider } from './ShellContext';

const navigateMock = vi.fn();
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => navigateMock };
});

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAbout: vi.fn(() => Promise.resolve({ version: '1.6.0' })),
  getAlerts: vi.fn(() => Promise.resolve({ groups: [], truncated: false, other_docs: 0 })),
  getInvestigations: vi.fn(() => Promise.resolve([])),
  getConfig: vi.fn(() => Promise.resolve({ groups: [], tokens: [], users: [], dangerHost: '' })),
  listMachines: vi.fn(),
  searchEntityIndex: vi.fn(),
  signOut: vi.fn(),
  getNeedsYouItems: vi.fn(),
  getRuleDecisions: vi.fn(),
}));

const EMPTY_PAGE = { rows: [], total: 0, limit: 8, offset: 0, sort: 'last_seen' as const, dir: 'desc' as const };
const WAITING = 'ET POLICY Example TLS client';
const STANDING = 'ET INFO Example update check';

async function openPalette() {
  render(
    <MemoryRouter>
      <ShellProvider>
        <CommandPalette />
      </ShellProvider>
    </MemoryRouter>,
  );
  fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
  await screen.findByRole('combobox');
}

function type(text: string) {
  fireEvent.change(screen.getByRole('combobox'), { target: { value: text } });
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(listMachines).mockResolvedValue(EMPTY_PAGE);
  vi.mocked(searchEntityIndex).mockResolvedValue({ q: '', hits: [] });
  vi.mocked(getNeedsYouItems).mockResolvedValue({
    total: 1,
    items: [
      {
        type: 'rule',
        id: ruleKeyOf(WAITING),
        title: WAITING,
        detail: '',
        since: '2026-10-01T00:00:00Z',
        href: `/needs-you/rule/${ruleKeyOf(WAITING)}`,
        count: 471,
        confident: 470,
        weak: 1,
      },
      {
        type: 'investigation',
        id: 'inv-1',
        title: 'ET POLICY Example TLS session',
        detail: '',
        since: null,
        href: '/investigation/inv-1',
      },
    ],
  });
  vi.mocked(getRuleDecisions).mockResolvedValue({
    standing: [
      {
        id: 4,
        ruleName: STANDING,
        decision: 'standing',
        by: 'ana',
        at: '2026-11-10T08:00:00Z',
        endsAt: '2026-12-10T08:00:00Z',
        acknowledged: 37,
      },
    ],
    ended: [],
  });
});

describe('CommandPalette: rule decisions', () => {
  it('finds a rule with open false positives and opens its page', async () => {
    await openPalette();
    type('example tls');
    const hit = await screen.findByRole('option', { name: new RegExp(`${WAITING}.*Rules`) });
    expect(hit).toHaveTextContent('Rule decision. 471 open false positives.');
    // The investigation of the list is no rule hit.
    expect(screen.queryByRole('option', { name: /Example TLS session.*Rules/ })).toBeNull();
    fireEvent.click(hit);
    expect(navigateMock).toHaveBeenCalledWith(`/needs-you/rule/${ruleKeyOf(WAITING)}`);
  });

  it('finds the rule of a standing decision in force and builds its key from the name', async () => {
    await openPalette();
    type('update check');
    const hit = await screen.findByRole('option', { name: new RegExp(`${STANDING}.*Rules`) });
    expect(hit).toHaveTextContent('A standing decision is in force until 2026-12-10 08:00 UTC.');
    fireEvent.click(hit);
    expect(navigateMock).toHaveBeenCalledWith(`/needs-you/rule/${ruleKeyOf(STANDING)}`);
  });

  // NEGATIVE CONTROL: a source that does not answer gives no hit and does
  // not take the other source down.
  it('keeps the hits of one source when the other one fails', async () => {
    vi.mocked(getRuleDecisions).mockRejectedValue(new Error('503'));
    await openPalette();
    type('example');
    expect(await screen.findByRole('option', { name: new RegExp(`${WAITING}.*Rules`) })).toBeTruthy();
    await waitFor(() => expect(getRuleDecisions).toHaveBeenCalled());
    expect(screen.queryByRole('option', { name: new RegExp(STANDING) })).toBeNull();
  });
});
