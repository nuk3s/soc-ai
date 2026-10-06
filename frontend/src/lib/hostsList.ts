// ---------------------------------------------------------------------------
// The Hosts list state, in the URL.
//
// The list kept its search, filters, sort and page in component memory, so
// Back, reload and the host page breadcrumb all landed on a reset list
// (dogfood 2026-10-02, U2). The URL now holds every one of them. This module
// owns the URL shape, so the list, the summary cards and the machine page
// breadcrumb read and write one spelling.
//
// Defaults stay out of the URL: `/hosts` is the landing list, and a link
// that names only the filter it applies stays short.
// ---------------------------------------------------------------------------

import type { MachineQuery } from './api';
import type { MachineSortKey, SortDir } from './types';

export const HOSTS_PAGE_SIZE = 50;

export const MACHINE_SORT_KEYS: readonly MachineSortKey[] = [
  'name',
  'address',
  'role',
  'agent',
  'events',
  'first_seen',
  'last_seen',
];

export const DEFAULT_MACHINE_SORT: MachineSortKey = 'last_seen';

/** The first direction a header click applies. Names and addresses read A to
 *  Z; counts and times read biggest and newest first. */
export const FIRST_DIR: Record<MachineSortKey, SortDir> = {
  name: 'asc',
  address: 'asc',
  role: 'asc',
  agent: 'asc',
  events: 'desc',
  first_seen: 'desc',
  last_seen: 'desc',
};

export interface HostsListState {
  q: string;
  sort: MachineSortKey;
  dir: SortDir;
  /** A role slug, `unknown`, `low_confidence`, `stale`, or '' for any. */
  role: string;
  agent: '' | 'yes' | 'no';
  activity: 'active' | 'all';
  seen: '' | 'new';
  declared: '' | 'yes' | 'no';
  /** 1-based. */
  page: number;
}

/** The list state the URL names. A value the API would refuse reads as the
 *  default, so a hand-edited link cannot put the list into an error. */
export function readListState(params: URLSearchParams): HostsListState {
  const sortRaw = params.get('sort') as MachineSortKey | null;
  const sort = sortRaw && MACHINE_SORT_KEYS.includes(sortRaw) ? sortRaw : DEFAULT_MACHINE_SORT;
  const dirRaw = params.get('dir');
  const dir: SortDir = dirRaw === 'asc' || dirRaw === 'desc' ? dirRaw : FIRST_DIR[sort];
  const agent = params.get('agent');
  const declared = params.get('declared');
  const page = Number.parseInt(params.get('page') ?? '', 10);
  return {
    q: (params.get('q') ?? '').trim(),
    sort,
    dir,
    role: (params.get('role') ?? '').trim(),
    agent: agent === 'yes' || agent === 'no' ? agent : '',
    activity: params.get('activity') === 'all' ? 'all' : 'active',
    seen: params.get('seen') === 'new' ? 'new' : '',
    declared: declared === 'yes' || declared === 'no' ? declared : '',
    page: Number.isFinite(page) && page > 1 ? page : 1,
  };
}

/** The keys this module owns. Other params (`conflicts`, `health`) pass
 *  through a write untouched. */
const OWNED = ['q', 'sort', 'dir', 'role', 'agent', 'activity', 'seen', 'declared', 'page'];

/**
 * Apply a patch to the list URL. A patch that changes anything but `page`
 * resets the page to 1 in the same write, so a new search or filter is one
 * request. A null or empty value removes the key.
 */
export function patchListParams(
  prev: URLSearchParams,
  patch: Partial<Record<keyof HostsListState, string | number | null>>,
): URLSearchParams {
  const next = new URLSearchParams(prev);
  for (const [key, value] of Object.entries(patch)) {
    if (!OWNED.includes(key)) continue;
    if (value == null || value === '') next.delete(key);
    else next.set(key, String(value));
  }
  const pageOnly = Object.keys(patch).every((k) => k === 'page');
  if (!pageOnly) next.delete('page');
  // Defaults stay out of the URL.
  if (next.get('page') === '1') next.delete('page');
  if (next.get('activity') === 'active') next.delete('activity');
  const sortRaw = next.get('sort') as MachineSortKey | null;
  const sort = sortRaw && MACHINE_SORT_KEYS.includes(sortRaw) ? sortRaw : DEFAULT_MACHINE_SORT;
  if (next.get('dir') === FIRST_DIR[sort]) next.delete('dir');
  if (sort === DEFAULT_MACHINE_SORT) next.delete('sort');
  return next;
}

/** A list link that applies these filters over the default list. */
export function listHref(patch: Partial<Record<keyof HostsListState, string | null>>): string {
  const qs = patchListParams(new URLSearchParams(), patch).toString();
  return qs ? `/hosts?${qs}` : '/hosts';
}

/** The API query for this list state. */
export function machineQuery(state: HostsListState): MachineQuery {
  return {
    q: state.q || undefined,
    sort: state.sort,
    dir: state.dir,
    role: state.role || undefined,
    agent: state.agent || undefined,
    activity: state.activity,
    seen: state.seen || undefined,
    declared: state.declared || undefined,
    limit: HOSTS_PAGE_SIZE,
    offset: (state.page - 1) * HOSTS_PAGE_SIZE,
  };
}

/** The path a machine page lives at. The key carries a colon, so the segment
 *  is percent-encoded. */
export function machineHref(key: string): string {
  return `/hosts/${encodeURIComponent(key)}`;
}

// ---- the way back -----------------------------------------------------------

/** Router state the list hands a machine page. `fromList` is the list URL,
 *  so the breadcrumb knows the previous history entry is the list. */
export interface HostsLocationState {
  fromList?: string;
}

const URL_KEY = 'soc-ai:hosts-list:url';
const SCROLL_KEY = 'soc-ai:hosts-list:scroll';

function store(): Storage | null {
  try {
    return typeof sessionStorage === 'undefined' ? null : sessionStorage;
  } catch {
    return null;
  }
}

/** Remember the list URL. The breadcrumb returns here when the history has
 *  no list entry to go back to. */
export function rememberListUrl(search: string): void {
  try {
    store()?.setItem(URL_KEY, `/hosts${search}`);
  } catch {
    /* storage blocked: the breadcrumb falls back to /hosts */
  }
}

export function listUrlToReturnTo(): string {
  try {
    const url = store()?.getItem(URL_KEY);
    return url && url.startsWith('/hosts') && !url.startsWith('/hosts/') ? url : '/hosts';
  } catch {
    return '/hosts';
  }
}

/** Remember how far down the list the operator scrolled, for this URL. */
export function rememberListScroll(search: string, top: number): void {
  try {
    store()?.setItem(SCROLL_KEY, JSON.stringify({ search, top }));
  } catch {
    /* storage blocked */
  }
}

/** The scroll position saved for exactly this list URL, or null. */
export function savedListScroll(search: string): number | null {
  try {
    const raw = store()?.getItem(SCROLL_KEY);
    if (!raw) return null;
    const saved = JSON.parse(raw) as { search?: unknown; top?: unknown };
    return saved.search === search && typeof saved.top === 'number' ? saved.top : null;
  } catch {
    return null;
  }
}

/** The element that scrolls the list: the shell's content pane, or the
 *  document when the screen is mounted outside the shell. */
export function scrollParent(el: HTMLElement | null): HTMLElement | null {
  let node = el?.parentElement ?? null;
  while (node) {
    const style = typeof getComputedStyle === 'function' ? getComputedStyle(node) : null;
    const overflowY = style?.overflowY ?? '';
    if (overflowY === 'auto' || overflowY === 'scroll') return node;
    node = node.parentElement;
  }
  return (document.scrollingElement as HTMLElement | null) ?? null;
}

// ---- the age of a row -------------------------------------------------------

/** An agent report older than this marks a list row stale. */
export const AGENT_STALE_HOURS = 24;

/** What the list knows about the sweep its rows come from. */
export interface ListSweep {
  /** Whether sweeps run on a schedule. null when the screen does not know. */
  scheduleEnabled: boolean | null;
  /** The age of the newest sweep in hours, from the summary. null when no
   *  sweep is on record or the summary is not read. */
  staleHours: number | null;
}

/**
 * The tooltip of the stale marker on one row, or null for no marker.
 *
 * The list reads the agent state and the last-seen time from the last sweep.
 * With the schedule off, the range listed an agent as last seen "3d ago"
 * while its machine page read live activity from 52 minutes before. The
 * marker says the row is old and why.
 */
export function agentStaleTitle(
  lastReport: string | null | undefined,
  sweep: ListSweep,
  now: number = Date.now(),
): string | null {
  if (!lastReport) return null;
  const at = Date.parse(lastReport);
  if (!Number.isFinite(at)) return null;
  const hours = (now - at) / 3_600_000;
  if (hours <= AGENT_STALE_HOURS) return null;
  const parts = [
    `The agent last reported ${Math.floor(hours)} h ago.`,
    'The list shows the state at the last sweep.',
  ];
  if (sweep.scheduleEnabled === false) parts.push('Automatic sweeps are off.');
  parts.push(
    sweep.staleHours != null
      ? `The last sweep ran ${Math.round(sweep.staleHours)} h ago.`
      : 'The time of the last sweep is not known.',
  );
  parts.push('The machine page shows live activity.');
  return parts.join(' ');
}
