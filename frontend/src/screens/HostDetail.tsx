import { AlertTriangle, ChevronLeft, RotateCw, Server } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Link, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { DOCK_SAFE_AREA_CLASS } from '../components/ChatDock';
import { HostActivityRow } from '../components/HostActivityRow';
import { HostAddresses } from '../components/HostAddresses';
import { HostBriefing } from '../components/HostBriefing';
import { HostChatDock } from '../components/HostChatDock';
import { HostFacts, HostUnknowns } from '../components/HostFacts';
import { HostHero } from '../components/HostHero';
import { HostKpis } from '../components/HostKpis';
import { Panel, PanelHeader } from '../components/Panel';
import {
  EmptyState,
  ErrorState,
  LoadingState,
  NotFoundState,
  Spinner,
  StaleNotice,
} from '../components/States';
import {
  getDossier,
  getDossierRefreshStatus,
  getDossierSummary,
  getHostActivity,
  getMachine,
  getMe,
  isNotFound,
  resolveMachine,
  startDossierRefresh,
} from '../lib/api';
import { cn } from '../lib/cn';
import { activityState } from '../lib/hostActivity';
import { isMachineKey, isResolved, portsView, roleVocabulary } from '../lib/hostDossier';
import { listUrlToReturnTo, machineHref, type HostsLocationState } from '../lib/hostsList';
import { isIpKey } from '../lib/ip';
import { plural } from '../lib/plural';
import { SHOWN_ERRORS, sweepErrorList } from '../lib/sweepErrors';
import { absTime } from '../lib/timeRange';
import type { Dossier, DossierRefreshStatus, HostActivityRange, MachineDetail } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { BehaviouralProfile } from '../components/BehaviouralProfile';
import { HostObservations } from '../components/HostObservations';
import { LeadsStrip } from '../components/LeadsStrip';

/** What the route segment resolved to. Each carries the segment it answers
 *  for, because useAsync keeps the last answer while the next one loads. */
type Resolution =
  | { param: string; kind: 'skip' }
  | { param: string; kind: 'machine'; key: string }
  | { param: string; kind: 'none' };

/** The page's main read: a machine, or one address dossier. */
interface HostRead {
  param: string;
  machine: MachineDetail | null;
  dossier: Dossier | null;
  /** A machine key from before a merge, and the key that holds it now. */
  moved?: string;
}

// ---------------------------------------------------------------------------
// Sweep health for a NON-admin: GET /api/v1/dossiers/sweep-health.
//
// `GET /dossiers/refresh` is admin-gated because its `last_summary` carries the
// sweep's raw failure strings; the projection is the CLOSED four-field record
// (running / degraded / last_run / error count) the backend serves to any
// authenticated caller, so the never-seen panel below can stop describing a
// dead sweep as a sensor that looked. Fetched here rather than through
// lib/api.ts deliberately: lib/ belongs to an in-flight branch, and this moves
// there when it frees up (the sweepErrors.ts precedent — Hosts carries the same
// copy for the same reason). No login redirect on a failure either: a failed
// read leaves the sweep 'unreadable', and every other request on this page
// still goes through lib/api's own expiry handoff.
// ---------------------------------------------------------------------------

interface SweepHealth {
  running: boolean;
  degraded: boolean;
  last_run: string | null;
  error_count: number;
}

async function getSweepHealth(): Promise<SweepHealth> {
  const token = import.meta.env.VITE_API_TOKEN as string | undefined;
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch('/api/v1/dossiers/sweep-health', {
    credentials: 'include',
    signal: AbortSignal.timeout(20_000),
    headers,
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as SweepHealth;
}

/** One shape for BOTH status reads, so the panel keys off what is known rather
 *  than which route this caller was allowed to ask. `errors` is the admin
 *  read's extra; the projection leaves it empty and `errorCount` carries the
 *  piece of the verdict that crosses the role boundary. */
interface SweepStatusRead {
  running: boolean;
  last_run: string | null;
  degraded: boolean;
  errors: string[];
  errorCount: number;
}

const fromFullStatus = (s: DossierRefreshStatus): SweepStatusRead => {
  const errors = sweepErrorList(s.last_summary);
  return {
    running: s.running,
    last_run: s.last_run,
    degraded: errors.length > 0,
    errors,
    errorCount: errors.length,
  };
};

const fromProjection = (h: SweepHealth): SweepStatusRead => ({
  running: h.running,
  last_run: h.last_run,
  degraded: h.degraded,
  errors: [],
  errorCount: h.error_count,
});

/** The ports a host answers on, per the sweep, or null when the field never
 *  resolved. "We do not know" is not "none", and they send an operator to
 *  different places — which is why null survives to the KPI tile. */
function servicePorts(dossier: Dossier): string[] | null {
  const f = dossier.fields.find((row) => row.field === 'services_offered');
  if (!f || !isResolved(f)) return null;
  // Through the same normalizer the fact row reads, so the tile and the row
  // cannot disagree about a payload shape. Payload order is kept, not sorted:
  // the collector ranks by connection count, so the head is the busiest.
  return portsView(f.value_json)?.ports ?? null;
}

/**
 * The ports the BEHAVIOURAL PROFILE has this host serving, or null when no
 * plane on the grid can answer the dimension.
 *
 * The profile is the longer read: the panel further down the page builds it
 * from up to 30 days of history, while the services fact above is one sweep's
 * conclusion. On the range they disagreed by a port, and the page printed 7 in
 * the card and 8 in the panel (dogfood 2026-09-17).
 *
 * `measured` over an empty set is an ANSWER — this host serves nothing — so it
 * returns an empty list rather than falling through to the sweep. Only
 * coverage the profile cannot speak for returns null.
 *
 * The members are bare port numbers. The aggregation keys on
 * `destination.port` alone, so nothing here knows the protocol, and the "tcp/"
 * the sweep's own payload carries would be invented.
 */
function profileServedPorts(dossier: Dossier): string[] | null {
  const d = dossier.profile?.find((row) => row.dimension === 'served_ports');
  if (!d) return null;
  if (d.coverage !== 'measured' && d.top.length === 0) return null;
  // Busiest first, the order the wire already holds them in.
  return d.top.map(([port]) => port);
}

/** The start of the newest volume bar that holds an event, or null. The
 *  activity read is live; the dossier's last_seen is as old as the last sweep. */
export function newestActivity(volume: { ts: string; events: number }[] | undefined): string | null {
  let best: string | null = null;
  for (const point of volume ?? []) {
    if (point.events > 0 && (best == null || point.ts > best)) best = point.ts;
  }
  return best;
}

/**
 * One host: what it IS (swept, cached, survives a grid outage) and what it is
 * DOING (read live off Security Onion, degrades on its own).
 *
 * The page leads with the composed answer — identity sentence, then the KPI
 * cards that size the machine, then the why-care strip (policy note,
 * criticality, coverage, open disagreements) — because the analyst arriving
 * from an alert needs "what is this machine and why should I care" in seconds,
 * not a tour of the schema. Everything resolved gets a row; everything unknown
 * collapses to one line.
 *
 * There is no stored "current value" anywhere in this feature — every answer
 * is the resolver's read-time output, operator declarations first. Each
 * mutation answers with the WHOLE re-resolved host, so the response replaces
 * the page rather than patching a field.
 */
export function HostDetail() {
  const { key: rawParam = '' } = useParams();
  const param = rawParam.trim();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  // Deep-link target: the conflicts queue and the reconsider notifications
  // point at one field; landing with no sign of which was meant is the same as
  // not linking at all.
  const focusField = searchParams.get('field');
  // The address a link named. Old links, /entity redirects and bookmarks name
  // an address; the page resolves it to the machine and keeps it in focus.
  const focusAddress = searchParams.get('address');
  const keyed = isMachineKey(param);
  const paramIsIp = isIpKey(param);
  // The record page of one address. The machine page links here, so a
  // declaration on an address that is not the primary has a page to live on.
  const addressOnly = !keyed && paramIsIp && searchParams.get('view') === 'address';

  // An address or a name resolves to a machine key first.
  const resolution = useAsync<Resolution>(
    () =>
      keyed || !param
        ? Promise.resolve({ param, kind: 'skip' as const })
        : resolveMachine(param).then(
            (r) => ({ param, kind: 'machine' as const, key: r.key }),
            (err: unknown) => {
              if (isNotFound(err)) return { param, kind: 'none' as const };
              throw err;
            },
          ),
    [param, keyed],
  );
  const resolved = resolution.data && resolution.data.param === param ? resolution.data : null;
  // The resolve read failed for a reason other than "no machine". A FOREGROUND
  // failure for this segment.
  const resolveFailed = !keyed && !resolved && !!resolution.error && !resolution.loading;

  // Replace the URL with the machine key. `replace` keeps the address URL out
  // of history, and the router state rides along so the breadcrumb still
  // knows the list is the entry behind this one.
  const redirectTo = !addressOnly && resolved?.kind === 'machine' ? resolved.key : null;
  useEffect(() => {
    if (!redirectTo) return;
    const next = new URLSearchParams(searchParams);
    if (paramIsIp && !next.has('address')) next.set('address', param);
    const qs = next.toString();
    navigate(`${machineHref(redirectTo)}${qs ? `?${qs}` : ''}`, {
      replace: true,
      state: location.state,
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [redirectTo, param]);

  // An address that no machine holds, or whose machine could not be read,
  // keeps the page of the address alone. A 404 from the resolve read lands
  // here, and the address dossier then says "never seen" when the sweep has
  // no record.
  const addressMode =
    !keyed && paramIsIp && (addressOnly || resolved?.kind === 'none' || resolveFailed);
  const mode: 'machine' | 'address' | null = keyed ? 'machine' : addressMode ? 'address' : null;
  // A name that no machine answers to.
  const unknownName = !keyed && !paramIsIp && resolved?.kind === 'none';
  const nameResolveFailed = !keyed && !paramIsIp && resolveFailed;

  const read = useAsync<HostRead | null>(() => {
    if (mode === 'machine') {
      return getMachine(param).then(
        (m) => ({ param, machine: m, dossier: m.dossier }),
        async (err: unknown) => {
          if (!isNotFound(err)) throw err;
          // A key from before a merge: the value it carries may resolve to the
          // machine that absorbed it.
          const tail = param.slice(param.indexOf(':') + 1);
          const r = await resolveMachine(tail).catch(() => null);
          if (r && r.key !== param) return { param, machine: null, dossier: null, moved: r.key };
          throw err;
        },
      );
    }
    if (mode === 'address') {
      return getDossier(param).then((d) => ({ param, machine: null, dossier: d }));
    }
    return Promise.resolve(null);
  }, [param, mode]);
  const current = read.data && read.data.param === param ? read.data : null;
  const { loading, error, refetch, lastUpdated } = read;
  const data = current?.dossier ?? null;
  const machine = current?.machine ?? null;
  const moved = current?.moved ?? null;
  useEffect(() => {
    if (!moved) return;
    navigate(`${machineHref(moved)}${location.search}`, { replace: true, state: location.state });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [moved]);

  // The address every per-address read below uses: the machine's primary
  // address, or the address of an address page. The server expands the
  // observations read to every address of the machine.
  const ip = data?.ip ?? machine?.primary_ip ?? (mode === 'address' ? param : '');

  // The classifier's role vocabulary, from the network summary (best-effort,
  // unpolled). It feeds the declare editor's role datalist so this form offers
  // the same roles the host list's filter does — both read one wire source
  // instead of each carrying its own copy. A slow or failed summary just leaves
  // the editor on its ROLE_VOCABULARY fallback.
  const summary = useAsync(() => getDossierSummary(), []);
  const roleVocab = roleVocabulary(summary.data?.role_vocabulary);

  // The live half, fetched SEPARATELY from the dossier above — different
  // freshness contracts, so each gets its own request, error and degraded
  // state. Not polled: this is a page you land on to read, and a background
  // poll here is a repeated multi-aggregation grid query per open tab.
  const [range, setRange] = useState<HostActivityRange>('24h');
  // The response carries the window it was asked for, so a panel is always
  // labelled with the window its data actually describes — not the one just
  // clicked while the request is still in flight.
  const activity = useAsync(
    () =>
      ip
        ? getHostActivity(ip, range).then((payload) => ({ payload, range }))
        : Promise.resolve(null),
    [ip, range],
  );
  const shown = activity.data?.payload ?? null;
  const shownRange = activity.data?.range ?? range;
  const state = activityState(shown, activity.error);

  // The last mutation response, which supersedes the fetched copy until a
  // fresh GET lands (the effect drops it when `data` is replaced).
  const [applied, setApplied] = useState<Dossier | null>(null);
  useEffect(() => setApplied(null), [data]);
  const dossier = applied ?? data;

  // The chat dock's scope label prefers the name a human uses — the SAME
  // derivation HostHero applies, so the header and the dock cannot disagree
  // about what this machine is called. The address is the honest fallback.
  const hostnameField = dossier?.fields.find((f) => f.field === 'hostname');
  const hostname =
    (machine?.name ?? '').trim() ||
    (hostnameField && isResolved(hostnameField)
      ? (hostnameField.value ?? '').trim() || null
      : null);
  // A field named in the URL describes the primary address unless the link
  // also named another address. That address opens in the Addresses section
  // with the field marked there.
  const primaryFocusField =
    !machine || !focusAddress || focusAddress === machine.primary_ip ? focusField : null;

  // The SPA's only role source is /me (Sidebar does the same). A failure
  // leaves the role UNKNOWN rather than "analyst": hiding the controls on a
  // network blip would look like the feature is missing, so the write is
  // allowed to go and the 403 speaks for itself.
  const [role, setRole] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    getMe()
      .then((m) => {
        if (alive) setRole(m.role);
      })
      .catch(() => {
        if (alive) setRole('unknown');
      });
    return () => {
      alive = false;
    };
  }, []);
  const canDeclare = role === 'admin' || role === 'unknown';
  const adminBlocked = role !== null && role !== 'admin' && role !== 'unknown';

  // The on-page sweep: the build-error banner's retry and the never-seen
  // page's one action.
  const [sweeping, setSweeping] = useState(false);
  const [sweepNote, setSweepNote] = useState<string | null>(null);
  useEffect(() => setSweepNote(null), [ip]);

  // THE SWEEP'S OWN HEALTH, read wherever this page speaks for the sweep — the
  // never-seen panel and the failed-build banner. Both used to describe the
  // sweep as a working sensor without ever asking it: the never-seen copy
  // promised that "the next sweep will pick it up" while every sweep was coming
  // back blind against a grid that could not be read, and the page after a
  // kickoff was byte-identical to the same page on a healthy estate.
  //
  // The FULL status is an admin-gated GET, exactly as on the Hosts screen; a
  // role that cannot read it asks the closed sweep-health projection instead,
  // so the answer is no longer UNKNOWN for an analyst — the blind spot the
  // admin-only read left open was this page's own bug, narrowed to the one
  // audience least able to check. An unknown role (getMe failed) tries the full
  // read, same as the declare controls: hiding on a blip would misreport, and
  // the 403 lands in `sweepUnreadable`, which is honest. Nothing is asked until
  // the role is known.
  //
  // Polling is armed but paused unless a sweep is in flight: a sweep is a rare
  // operator-initiated act, not a live console. The kickoff below unpauses it.
  const speaksForTheSweep = !!dossier && (!dossier.found || !!dossier.build_error);
  const wantSweepHealth = speaksForTheSweep && role !== null;
  const canReadFullSweep = canDeclare;
  const sweepRunningRef = useRef(false);
  const sweepHealth = useAsync<SweepStatusRead | null>(
    () => {
      if (!wantSweepHealth) return Promise.resolve(null);
      if (canReadFullSweep) return getDossierRefreshStatus().then(fromFullStatus);
      return getSweepHealth().then(fromProjection);
    },
    [wantSweepHealth, canReadFullSweep],
    { refetchInterval: 4000, pauseWhen: () => !sweepRunningRef.current },
  );
  const sweepRunning = !!sweepHealth.data?.running;
  sweepRunningRef.current = sweepRunning;
  const sweepErrors = sweepHealth.data?.errors ?? [];
  const sweepErrorCount = sweepHealth.data?.errorCount ?? 0;
  // The last sweep came back blind and no newer one is in flight to overturn
  // that. A sweep that IS running supersedes the last one's verdict — the same
  // rule the Hosts screen's degraded note follows — so the healthy explanation
  // stands until there is an outcome to report.
  const sweepBlind = !!sweepHealth.data?.degraded && !sweepRunning;
  // The page asked after the sweep and got nothing back. Distinct from the
  // 'unknown' below it, which is a page that has not asked yet: "we could not
  // check" and "we did not check" are both short of a record, but only the
  // first is something to tell the reader, and neither supports the promise. A
  // FOREGROUND failure only — useAsync keeps last-good data through a failed
  // background poll, and a record read once is better evidence than the blip
  // that followed it.
  const sweepUnreadable = !!sweepHealth.error && !sweepHealth.data;
  // What the page KNOWS about the sweep, on the panel that speaks for it.
  // 'unknown' is a real answer — the state before the role (and so the route)
  // is known — and it is the state a test has to be able to wait past, or a
  // control asserting the healthy copy passes on a page that has not finished
  // asking yet.
  const sweepFacet = sweepBlind
    ? 'blind'
    : sweepRunning
      ? 'running'
      : sweepUnreadable
        ? 'unreadable'
        : sweepHealth.data
          ? 'read'
          : 'unknown';

  // A sweep ends, and the host it may have just built is worth re-reading: that
  // re-read is the reload this page used to ask the operator to perform by
  // hand, into copy that had no way of knowing how the sweep went. Two ways to
  // see one end, because there are two ways to have a sweep to watch:
  //
  //   * THIS PAGE WATCHED IT RUN — its own or anyone's. The running note is
  //     printed off the server's status, so it appears for a sweep started from
  //     the Hosts list and for one already in flight when the analyst arrived,
  //     and "this page updates when it finishes" has to be true for those too.
  //     An admin who starts a sweep on Hosts, clicks into a never-seen host and
  //     waits as instructed used to sit on "never seen" after the sweep had
  //     built that very host. Mirrors the Hosts screen's own transition.
  //   * A SWEEP THIS PAGE STARTED ended without any poll catching it running.
  //     `last_run` advances when a run completes, and comparing against the run
  //     we clicked over is what stops the first status read after the kickoff
  //     (which may still describe the PREVIOUS run) retiring the note the click
  //     had just posted.
  //
  // Only the second clears the kickoff receipt. That note belongs to this tab's
  // click, and its other answers — 'dossier disabled' above all — describe a
  // run that never started and so will never end to retire it.
  const startedSweep = useRef<string | null | undefined>(undefined);
  const watchedSweep = useRef(false);
  useEffect(() => {
    const status = sweepHealth.data;
    if (sweepHealth.loading || !status) return;
    if (status.running) {
      watchedSweep.current = true;
      return;
    }
    const watched = watchedSweep.current;
    watchedSweep.current = false;
    const startedFrom = startedSweep.current;
    const ours = startedFrom !== undefined && status.last_run !== startedFrom;
    if (ours) {
      startedSweep.current = undefined;
      setSweepNote(null);
    }
    // Every other status read is a poll reporting no change, and re-reading the
    // host on those would put a four-second query loop on every host page left
    // open.
    if (!watched && !ours) return;
    refetch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sweepHealth.data, sweepHealth.loading]);

  const sweepNow = async () => {
    setSweeping(true);
    try {
      const status = await startDossierRefresh();
      if (status.note === 'dossier disabled') {
        // Nothing was started, so there is no run to follow.
        setSweepNote('No sweep started. The host dossier is off in Config.');
      } else if (status.note === 'already running') {
        startedSweep.current = sweepHealth.data?.last_run ?? null;
        setSweepNote('A sweep is already running. This page updates after the sweep finishes.');
      } else {
        startedSweep.current = sweepHealth.data?.last_run ?? null;
        setSweepNote('The sweep runs in the background. This page updates after the sweep finishes.');
      }
      // Arm the poll now rather than waiting out an interval: the POST claims
      // the running slot before it schedules anything, so the next status read
      // already knows a sweep is up.
      sweepHealth.refetch();
    } catch (err) {
      setSweepNote(err instanceof Error ? err.message : String(err));
    } finally {
      setSweeping(false);
    }
  };

  // The segment is still resolving, or the page is on its way to the machine
  // key. Either way there is nothing of this page's own to show yet.
  const settling =
    !!redirectTo ||
    !!moved ||
    (mode === null && !unknownName && !nameResolveFailed && (resolution.loading || !resolved));
  // Three ways to have no activity row: a name no machine answers to, an
  // address the sweep has never seen, and a read that failed. Keying on the
  // row's own precondition covers all three without flickering the toolbar in
  // during the initial load.
  const showActivityControls =
    !unknownName &&
    !nameResolveFailed &&
    (settling || loading ? !dossier || dossier.found : !!dossier && dossier.found);

  // Scroll the deep-linked field into view once it exists, ONCE per link and
  // not per render: every write replaces the dossier, and re-scrolling under an
  // operator mid-edit would fight them. Guarded: jsdom has no scrollIntoView.
  const scrolledFor = useRef<string | null>(null);
  useEffect(() => {
    if (!primaryFocusField || !dossier) return;
    const key = `${ip}:${primaryFocusField}`;
    if (scrolledFor.current === key) return;
    scrolledFor.current = key;
    const el = document.getElementById(`field-${primaryFocusField}`);
    (el as HTMLElement | null)?.scrollIntoView?.({ behavior: 'auto', block: 'center' });
  }, [primaryFocusField, dossier, ip]);

  // The way back to the list. When the list opened this page, the entry
  // behind this one IS the list, with its scroll position: go back to it.
  // Otherwise open the list URL the screen last held.
  const fromList = (location.state as HostsLocationState | null)?.fromList ?? null;
  const backTo = fromList ?? listUrlToReturnTo();
  const crumb = machine ? (machine.name ?? machine.primary_ip) : param;

  return (
    // The dock at the bottom right is fixed to the viewport. Without the
    // reservation it draws over the last Edit control on the facts panel.
    <div className={cn('px-[22px] pt-[18px] font-sans text-text', DOCK_SAFE_AREA_CLASS)}>
      <div className="mb-3.5 flex flex-wrap items-center gap-3">
        <Link
          to={backTo}
          data-testid="hosts-crumb"
          onClick={(e) => {
            if (!fromList) return;
            e.preventDefault();
            navigate(-1);
          }}
          className="flex items-center gap-1.5 text-[12.5px] text-dim hover:text-text"
        >
          <ChevronLeft size={13} /> Hosts
        </Link>
        <span className="text-ghost">/</span>
        <div data-testid="host-crumb-name" className="font-mono text-[15px] font-semibold">
          {crumb}
        </div>
        <div className="flex-1" />
        {showActivityControls && (
          <>
            <div className="flex items-center gap-1 rounded-control border border-border-input bg-surface-2 p-0.5">
              {(['24h', '7d'] as HostActivityRange[]).map((r) => (
                <button
                  key={r}
                  onClick={() => setRange(r)}
                  aria-pressed={range === r}
                  className={cn(
                    'rounded-[6px] px-2.5 py-1 font-mono text-[11.5px] font-semibold transition-colors',
                    range === r ? 'bg-accent/15 text-accent' : 'text-faint hover:text-text-2',
                  )}
                >
                  {r}
                </button>
              ))}
            </div>
            <button
              onClick={() => {
                // BOTH halves of the page. This re-read the activity charts
                // alone, which left the identity — the half a sweep changes,
                // and the half the page is named after — exactly as stale as
                // before the click, directly under a banner telling the
                // operator to "reload this page" once their sweep lands. It is
                // also the only control that makes a failed foreground read of
                // the dossier reachable, which is what the marker below says.
                refetch();
                activity.refetch();
              }}
              disabled={loading || activity.loading}
              title="Re-read this host and its activity"
              aria-label="Refresh host"
              className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-2.5 py-1.5 text-[11.5px] font-semibold text-text-2 hover:border-accent hover:text-text disabled:opacity-60"
            >
              {loading || activity.loading ? <Spinner size={11} /> : <RotateCw size={11} />}
              Refresh
            </button>
          </>
        )}
      </div>

      <div className="mx-auto max-w-workstation">
        {/* The machine read failed, so this page cannot say which machine
            holds the address. It says so above the page of the address,
            the "never seen" page included. */}
        {mode === 'address' && resolveFailed && (
          <div
            data-testid="host-resolve-failed"
            role="status"
            className="mb-3 flex flex-wrap items-start gap-x-3 gap-y-2 rounded-card border border-warn/30 bg-warn/[0.06] px-3.5 py-2.5 text-[12.5px] leading-[1.5] text-text-2"
          >
            <div className="min-w-0 flex-1">
              This page could not find the machine that holds this address. The page shows the
              address alone.
              <span className="mt-0.5 block text-[11.5px] text-dim">{resolution.error?.message}</span>
            </div>
            <button
              type="button"
              onClick={resolution.refetch}
              className="flex flex-none items-center gap-1.5 rounded-control border border-warn/40 px-2.5 py-1 text-[11.5px] font-semibold text-warn hover:bg-warn/15"
            >
              <RotateCw size={11} /> Retry
            </button>
          </div>
        )}
        {unknownName ? (
          <Panel>
            <PanelHeader icon={<Server size={15} />} title="No machine has this name" />
            <EmptyState>
              <div data-testid="host-unknown-name">
                No machine answers to <span className="font-mono text-dim">{param}</span>. The
                search reads every name, address, MAC and agent of every machine. Search the{' '}
                <Link to={`/hosts?q=${encodeURIComponent(param)}`} className="text-accent hover:underline">
                  Hosts list
                </Link>
                , or open the{' '}
                <Link to={`/entity/${encodeURIComponent(param)}`} className="text-accent hover:underline">
                  entity page
                </Link>{' '}
                for the investigations and findings that name it.
              </div>
            </EmptyState>
          </Panel>
        ) : nameResolveFailed ? (
          <ErrorState error={resolution.error!} onRetry={resolution.refetch} label="this host" />
        ) : settling || (loading && !dossier) ? (
          <LoadingState label="Loading host…" />
        ) : error && !dossier && isNotFound(error) ? (
          // The route itself 404'd. That is a different answer from "the sweep
          // has never seen this address" (200 + found:false, below), and from
          // a real outage, which keeps the alarm card and its Retry.
          <NotFoundState what="host" id={param} backTo="/hosts" backLabel="Back to Hosts" />
        ) : error && !dossier ? (
          <ErrorState error={error} onRetry={refetch} label="this host" />
        ) : !dossier ? null : !dossier.found ? (
          // 200 + found:false is a real answer, not a failure: the sweep has no
          // row for this address — different from "nothing notable", and the
          // page says so in exactly those words.
          //
          // What it may NOT do is go on to describe the sweep as a sensor that
          // looked. "Has never seen this address" and "the next sweep will pick
          // it up" are claims about a sweep this page had never asked after, and
          // over a blind one they are the reassurance that ends the
          // investigation. So the reassuring half is spoken only when the sweep
          // record supports it, and the database fact is spoken either way.
          <Panel>
            <PanelHeader icon={<Server size={15} />} title={ip} />
            <EmptyState>
              <div
                data-testid="host-never-seen"
                data-sweep={sweepFacet}
                className="mx-auto max-w-[560px] text-left"
              >
                {sweepBlind ? (
                  <>
                    <div
                      data-testid="host-never-seen-lead"
                      className="mb-2 text-[13px] leading-[1.6] text-dim"
                    >
                      The network sweep has no record of this address. The last sweep could not
                      read the network. The address may still be on your network.
                    </div>
                    <div
                      data-testid="host-sweep-blind"
                      className="rounded-card border border-warn/30 bg-warn/[0.06] px-3.5 py-2.5"
                    >
                      <div className="text-[12.5px] leading-[1.6] text-text-2">
                        The last sweep hit {plural(sweepErrorCount, 'error')}. The sweep could not
                        read the whole network. The sweep may never have looked at{' '}
                        <span className="font-mono">{ip}</span>. This page cannot say if the address
                        is on your network until a sweep reads the whole network.{' '}
                        {sweepErrors.length > 0
                          ? 'Another sweep runs the same queries. Read what failed first:'
                          : 'An admin can read what failed. An admin can start another sweep from the Hosts screen.'}
                      </div>
                      {/* The strings, not just how many — the same reason the
                          Hosts list prints them. This channel carries local
                          faults as well as grid ones, and a bare count sends the
                          operator off to wait on Security Onion for something
                          Security Onion will never fix. Admin only: the strings
                          are the reason the full status is gated, so the
                          projection a non-admin reads never carries them — for
                          that reader the verdict and the count stand alone. */}
                      {sweepErrors.length > 0 && (
                        <ul className="mt-1.5 space-y-0.5 text-[11.5px] text-dim">
                          {sweepErrors.slice(0, SHOWN_ERRORS).map((e, i) => (
                            <li key={i} className="truncate font-mono" title={e}>
                              {e}
                            </li>
                          ))}
                          {sweepErrors.length > SHOWN_ERRORS && (
                            <li className="text-faint">
                              and {(sweepErrors.length - SHOWN_ERRORS).toLocaleString()} more
                            </li>
                          )}
                        </ul>
                      )}
                    </div>
                  </>
                ) : sweepUnreadable ? (
                  <>
                    {/* The page asked how the sweep is doing and the read
                        failed. The absence is still a fact about the database
                        and is still worth stating; what may not follow it is a
                        promise about a sensor whose health this page had just
                        failed to establish. */}
                    <div
                      data-testid="host-never-seen-lead"
                      className="mb-2 text-[13px] leading-[1.6] text-dim"
                    >
                      The network sweep has no record of this address. This page has nothing to
                      report about the address. That is different from "nothing notable".
                    </div>
                    <div
                      data-testid="host-sweep-unreadable"
                      className="text-[12.5px] leading-[1.6] text-faint"
                    >
                      This page could not check the last sweep. The address{' '}
                      <span className="font-mono">{ip}</span> may be outside the ranges Security
                      Onion monitors. The last sweep may also have missed the address.
                      <span className="mt-0.5 block font-mono text-[11.5px] text-dim">
                        {sweepHealth.error?.message}
                      </span>
                    </div>
                  </>
                ) : (
                  <>
                    <div
                      data-testid="host-never-seen-lead"
                      className="mb-2 text-[13px] leading-[1.6] text-dim"
                    >
                      The network sweep has never seen this address. This page has nothing to
                      report about the address. That is different from "nothing notable".
                    </div>
                    <div className="text-[12.5px] leading-[1.6] text-faint">
                      The next sweep records <span className="font-mono">{ip}</span> if the address
                      is inside the ranges Security Onion monitors. The address must also show
                      enough traffic. The address never appears here if it is outside those ranges.
                    </div>
                  </>
                )}
                {/* THE OTHER LANE, on the one page with no room for it. The
                    copy above is about the sweep's DATABASE and survives an
                    outage; this page also put a LIVE question to Security Onion
                    — "is this address showing traffic right now" — and on a
                    host with a body the answer, or the failure to get one,
                    lands in HostActivityRow. A never-seen host has no row to
                    degrade, so a 503 here changed nothing at all on screen: the
                    pre-click capture in `stalled` waited twelve seconds for
                    this read, got a 503, and rendered a page identical to the
                    same page on a healthy estate.
                    Its own line rather than a rewrite of the sweep copy above:
                    the two lanes fail independently by design, and folding a
                    live-read failure into the sweep's verdict is how the page
                    would start reporting an outage it has not observed. */}
                {state === 'down' && (
                  <div
                    data-testid="host-activity-unread"
                    role="status"
                    className="mt-3 flex flex-wrap items-start gap-x-3 gap-y-2 rounded-card border border-warn/30 bg-warn/[0.06] px-3.5 py-2.5"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="text-[12.5px] leading-[1.6] text-text-2">
                        This page could not read the live activity for{' '}
                        <span className="font-mono">{ip}</span>. This page cannot say if the address
                        carries traffic now.
                      </div>
                      <div className="mt-0.5 text-[11.5px] leading-[1.5] text-dim">
                        {activity.error?.message}
                      </div>
                    </div>
                    {/* The page toolbar's Refresh is hidden on a host with no
                        body, so without this the failed read has no retry
                        anywhere on the screen. */}
                    <button
                      onClick={activity.refetch}
                      disabled={activity.loading}
                      className="flex flex-none items-center gap-1.5 rounded-control border border-warn/40 px-2.5 py-1 text-[11.5px] font-semibold text-warn hover:bg-warn/15 disabled:opacity-60"
                    >
                      <RotateCw size={11} /> Retry
                    </button>
                  </div>
                )}
                {/* A running sweep outranks the click's receipt: it comes off
                    the server, so it cannot go stale the way a note written at
                    kickoff can. The note below it carries the answers that mean
                    nothing started at all. */}
                {sweepRunning ? (
                  <div
                    data-testid="host-sweep-running"
                    className="mt-3 flex items-center gap-1.5 text-[12.5px] text-text-2"
                  >
                    <Spinner size={12} />A sweep is running now. This page updates after the sweep
                    finishes.
                  </div>
                ) : sweepNote ? (
                  <div className="mt-3 text-[12.5px] text-text-2">{sweepNote}</div>
                ) : (
                  canDeclare && (
                    <button
                      onClick={() => {
                        void sweepNow();
                      }}
                      disabled={sweeping}
                      className="mt-3 flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12px] font-semibold text-text-2 hover:border-accent hover:text-text disabled:opacity-60"
                    >
                      {sweeping ? <Spinner size={12} /> : <RotateCw size={12} />}
                      Sweep the network now
                    </button>
                  )
                )}
              </div>
            </EmptyState>
          </Panel>
        ) : (
          <>
            {/* The rebound warning outranks everything on the page: "this may
                not be the machine you think" has to be read BEFORE the line
                asserting which machine it is. */}
            {dossier.identity_rebound_at && (
              <div
                role="alert"
                className="mb-3 flex items-start gap-2 rounded-card border border-warn/40 bg-warn/[0.08] px-3.5 py-2.5 text-[12.5px] leading-[1.5] text-warn"
              >
                <AlertTriangle size={14} className="mt-0.5 flex-none" />
                <span>
                  A different machine may hold this address now. The rebound time is{' '}
                  {absTime(dossier.identity_rebound_at)}. The declarations below may describe a host
                  that no longer holds this address.
                </span>
              </div>
            )}

            {/* A failed build, in red, with the stored error and the retry.
                "Never looked" and "looked and it broke" demand different
                operator actions, and the old page made them the same screen. */}
            {dossier.build_error && (
              <div
                role="alert"
                className="mb-3 flex items-start gap-2 rounded-card border border-danger/40 bg-danger/[0.06] px-3.5 py-2.5 text-[12.5px] leading-[1.5]"
              >
                <AlertTriangle size={14} className="mt-0.5 flex-none text-danger" />
                <div className="min-w-0 flex-1">
                  <div className="font-semibold text-danger">
                    The last sweep failed on this host. The facts below may be out of date.
                  </div>
                  <div className="mt-0.5 break-words font-mono text-[12px] text-text-2">
                    {dossier.build_error}
                  </div>
                  {sweepNote && <div className="mt-1 text-[12px] text-dim">{sweepNote}</div>}
                </div>
                {canDeclare && !sweepNote && (
                  <button
                    onClick={() => {
                      void sweepNow();
                    }}
                    disabled={sweeping}
                    className="flex flex-none items-center gap-1.5 rounded-control border border-danger/40 px-2.5 py-1 text-[11.5px] font-semibold text-danger hover:bg-danger/10 disabled:opacity-60"
                  >
                    {sweeping ? <Spinner size={11} color="#f04438" /> : <RotateCw size={11} />}
                    Sweep again
                  </button>
                )}
              </div>
            )}

            {/* A failed foreground read with the page already populated. The
                `!dossier` gates above deliberately keep the content — but that
                left the failure with nowhere to appear at all, so the analyst
                went on reading a host page that had silently stopped being
                refreshed. Below the two alerts above, which are claims about
                the MACHINE; this is a claim about the page, and the rebound
                warning outranks everything by design. */}
            {error && (
              <StaleNotice
                since={lastUpdated}
                onRefresh={refetch}
                reason="refresh-failed"
                className="mb-3"
              />
            )}

            {/* The address page says why it is not the machine page. */}
            {mode === 'address' && !addressOnly && resolved?.kind === 'none' && (
              <div data-testid="host-no-machine" className="mb-3 text-[12px] text-faint">
                No machine holds this address. This page shows the address alone.
              </div>
            )}
            {addressOnly && (
              <div data-testid="host-address-only" className="mb-3 text-[12px] text-faint">
                This page shows one address and its record.{' '}
                {resolved?.kind === 'machine' && (
                  <Link
                    to={`${machineHref(resolved.key)}?address=${encodeURIComponent(param)}`}
                    className="font-semibold text-accent hover:underline"
                  >
                    Open the machine page
                  </Link>
                )}
              </div>
            )}

            <HostHero
              dossier={dossier}
              machine={machine}
              adminBlocked={adminBlocked}
              lastActivity={newestActivity(shown?.volume)}
            />

            {/* The cards lead (the owner's ask: KPIs and charts at the top),
                and the why-care strip sits directly under them — still above
                the fold, because "why should I care" cannot rank below a peer
                graph. */}
            {/* The profile's own served-ports set where it has one, so the
                card and the profile panel below it count the same ports. */}
            <HostKpis
              ip={dossier.ip}
              services={profileServedPorts(dossier) ?? servicePorts(dossier)}
              servicesSource={profileServedPorts(dossier) != null ? 'profile' : 'dossier'}
              activity={shown}
              state={state}
              range={shownRange}
            />

            <HostBriefing
              dossier={dossier}
              canDeclare={canDeclare}
              onApplied={setApplied}
              focusField={primaryFocusField}
            />

            {/* Every address of the machine, and its containers. */}
            {machine && (
              <HostAddresses machine={machine} focusAddress={focusAddress} focusField={focusField} />
            )}

            <HostActivityRow
              ip={dossier.ip}
              activity={shown}
              state={state}
              error={activity.error}
              loading={activity.loading}
              range={shownRange}
              onRetry={activity.refetch}
            />

            <HostFacts
              dossier={dossier}
              canDeclare={canDeclare}
              onApplied={setApplied}
              focusField={primaryFocusField}
              roleVocabulary={roleVocab}
              address={machine ? dossier.ip : undefined}
            />

            {/* Directly beneath the facts and their traffic pattern, because
                it is the same shape of claim with better provenance -- and
                because the two are currently computed separately and an
                analyst needs to see both to notice when they disagree. */}
            <BehaviouralProfile profile={dossier.profile ?? []} />
            {/* Every observation on this host, from every source. A repeated
                single signal is visible here before it forms a lead, so the
                panel sits between the profile and the leads it may feed. */}
            <HostObservations entityKey={ip} />
            {/* All, not New. A lead under a hunt and a lead already closed
                both belong to this host, and the host page listed neither. */}
            <LeadsStrip entityKey={ip} aliases={dossier.aliases} status="all" className="mt-4" />

            <HostUnknowns
              dossier={dossier}
              canDeclare={canDeclare}
              onApplied={setApplied}
              focusField={primaryFocusField}
              roleVocabulary={roleVocab}
            />
          </>
        )}
      </div>

      {/* Floating scoped chat, mounted the way Investigation mounts its dock:
          bottom-right, costing no layout space. Present for a never-seen host
          too — "has this address appeared in the logs at all?" is a question
          the agent can still answer from the grid. Absent only when there is
          no host to be about (not an address / the dossier read failed). */}
      {dossier && <HostChatDock ip={ip} hostname={hostname} />}
    </div>
  );
}
