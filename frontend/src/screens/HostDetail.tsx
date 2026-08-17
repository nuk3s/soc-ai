import { AlertTriangle, ChevronLeft, RotateCw, Server } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { HostActivityRow } from '../components/HostActivityRow';
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
  getMe,
  isNotFound,
  startDossierRefresh,
} from '../lib/api';
import { cn } from '../lib/cn';
import { activityState } from '../lib/hostActivity';
import { isResolved, portsView, roleVocabulary } from '../lib/hostDossier';
import { plural } from '../lib/plural';
import { SHOWN_ERRORS, sweepErrorList } from '../lib/sweepErrors';
import { absTime } from '../lib/timeRange';
import type { Dossier, DossierRefreshStatus, HostActivityRange } from '../lib/types';
import { useAsync } from '../lib/useAsync';

// request() collapses an HTTPException detail to its `hint`, so this IS the
// 404's own wording from routes_dossier._require_ip. Matching it lets the screen
// say "that is not an address" instead of "couldn't load", which is a different
// and much less useful thing to tell someone who mistyped a URL.
const NOT_AN_IP = /keyed on IP addresses/i;

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
  const { ip = '' } = useParams();
  const [searchParams] = useSearchParams();
  // Deep-link target: the conflicts queue and the reconsider notifications
  // point at one field; landing with no sign of which was meant is the same as
  // not linking at all.
  const focusField = searchParams.get('field');
  const { data, loading, error, refetch, lastUpdated } = useAsync(() => getDossier(ip), [ip]);

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
    () => getHostActivity(ip, range).then((payload) => ({ payload, range })),
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
    hostnameField && isResolved(hostnameField)
      ? (hostnameField.value ?? '').trim() || null
      : null;

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
        setSweepNote('The host dossier is switched off in Config, so nothing was swept.');
      } else if (status.note === 'already running') {
        startedSweep.current = sweepHealth.data?.last_run ?? null;
        setSweepNote('A sweep is already running — this page updates when it finishes.');
      } else {
        startedSweep.current = sweepHealth.data?.last_run ?? null;
        setSweepNote('Sweeping in the background — this page updates when it finishes.');
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

  const notAnIp = !!error && NOT_AN_IP.test(error.message);
  // Three ways to have no activity row: a segment that is not an address, an
  // address the sweep has never seen, and a read that failed. Keying on the
  // row's own precondition covers all three without flickering the toolbar in
  // during the initial load.
  const showActivityControls = loading ? !dossier || dossier.found : !!dossier && dossier.found;

  // Scroll the deep-linked field into view once it exists — ONCE per link, not
  // per render: every write replaces the dossier, and re-scrolling under an
  // operator mid-edit would fight them. Guarded: jsdom has no scrollIntoView.
  const scrolledFor = useRef<string | null>(null);
  useEffect(() => {
    if (!focusField || !dossier) return;
    const key = `${ip}:${focusField}`;
    if (scrolledFor.current === key) return;
    scrolledFor.current = key;
    const el = document.getElementById(`field-${focusField}`);
    (el as HTMLElement | null)?.scrollIntoView?.({ behavior: 'auto', block: 'center' });
  }, [focusField, dossier, ip]);

  return (
    <div className="px-[22px] pb-[60px] pt-[18px] font-sans text-text">
      <div className="mb-3.5 flex flex-wrap items-center gap-3">
        <Link to="/hosts" className="flex items-center gap-1.5 text-[12.5px] text-dim hover:text-text">
          <ChevronLeft size={13} /> Hosts
        </Link>
        <span className="text-ghost">/</span>
        <div className="font-mono text-[15px] font-semibold">{ip}</div>
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
        {loading && !dossier ? (
          <LoadingState label="Loading host…" />
        ) : notAnIp ? (
          <Panel>
            <PanelHeader icon={<Server size={15} />} title="Not a host address" />
            <EmptyState>
              <span className="font-mono text-dim">{ip}</span> is not an IP address, and hosts are
              keyed on addresses. Pick a host from the{' '}
              <Link to="/hosts" className="text-accent hover:underline">
                Hosts screen
              </Link>
              .
            </EmptyState>
          </Panel>
        ) : error && !dossier && isNotFound(error) ? (
          // The route itself 404'd — a different answer again from "the sweep
          // has never seen this address" (200 + found:false, below), and from
          // a real outage, which keeps the alarm card and its Retry.
          <NotFoundState what="host" id={ip} backTo="/hosts" backLabel="Back to Hosts" />
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
                      The network sweep has no record of this address — but the last sweep came
                      back blind, so that is not the same as this address being absent from your
                      network.
                    </div>
                    <div
                      data-testid="host-sweep-blind"
                      className="rounded-card border border-warn/30 bg-warn/[0.06] px-3.5 py-2.5"
                    >
                      <div className="text-[12.5px] leading-[1.6] text-text-2">
                        The last sweep hit {plural(sweepErrorCount, 'error')} and could not read
                        the whole network, so <span className="font-mono">{ip}</span> may be a host
                        it never got to look at. Until a sweep gets through, this page cannot tell
                        you whether the address is on your network or not.{' '}
                        {sweepErrors.length > 0
                          ? 'Sweeping again runs the same queries, so start with what failed:'
                          : 'An admin can read what failed and start another sweep from the Hosts screen.'}
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
                      The network sweep has no record of this address, so there is nothing to
                      report about it — which is different from "nothing notable".
                    </div>
                    <div
                      data-testid="host-sweep-unreadable"
                      className="text-[12.5px] leading-[1.6] text-faint"
                    >
                      This page could not check how the last sweep went, so it cannot tell you
                      whether <span className="font-mono">{ip}</span> is outside the ranges
                      Security Onion monitors or a host the last sweep never got to.
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
                      The network sweep has never seen this address, so there is nothing to report
                      about it — which is different from "nothing notable".
                    </div>
                    <div className="text-[12.5px] leading-[1.6] text-faint">
                      If <span className="font-mono">{ip}</span> is inside the ranges Security Onion
                      monitors, the next sweep will pick it up once it shows enough traffic. If it
                      is outside them, it will never appear here.
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
                        This page could not read <span className="font-mono">{ip}</span>'s live
                        activity either, so it cannot say whether the address is carrying traffic
                        right now.
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
                    <Spinner size={12} />A sweep is running now — this page updates when it
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
                  A different machine may hold this address now (rebound{' '}
                  {absTime(dossier.identity_rebound_at)}) — the declarations below may describe a
                  host that has moved on.
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
                    The last sweep failed on this host — what follows may be out of date.
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

            <HostHero dossier={dossier} adminBlocked={adminBlocked} />

            {/* The cards lead (the owner's ask: KPIs and charts at the top),
                and the why-care strip sits directly under them — still above
                the fold, because "why should I care" cannot rank below a peer
                graph. */}
            <HostKpis
              ip={dossier.ip}
              services={servicePorts(dossier)}
              activity={shown}
              state={state}
              range={shownRange}
            />

            <HostBriefing
              dossier={dossier}
              canDeclare={canDeclare}
              onApplied={setApplied}
              focusField={focusField}
            />

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
              focusField={focusField}
              roleVocabulary={roleVocab}
            />

            <HostUnknowns
              dossier={dossier}
              canDeclare={canDeclare}
              onApplied={setApplied}
              focusField={focusField}
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
