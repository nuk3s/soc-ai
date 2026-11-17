import { useEffect, useState, type ReactNode } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';

import {
  ApiError,
  getAnalyticHits,
  getHuntCatalog,
  markAnalyticShadowHitsRead,
  markObservationBenign,
  markShadowHitRead,
  setAnalyticStatus,
  startHuntConsole,
  type AnalyticHit,
  type AnalyticHitFilter,
  type AnalyticHitGroup,
  type AnalyticHits as AnalyticHitsPage,
  type HuntCatalog,
} from '../lib/api';
import { evaluations, loopRuns, runsInProfileSweep } from '../lib/analyticRuns';
import { entityPath as pathOfEntity } from '../lib/entityPath';
import { plural } from '../lib/plural';
import { absTime, ago } from '../lib/timeRange';
import {
  CHIP_ANALYTIC_REMOVED,
  CHIP_LIVE,
  CHIP_LOCAL,
  CHIP_NO_LEAD,
  CHIP_RECORDED_IN_SHADOW,
  CHIP_RECORDED_LIVE,
  CHIP_SHADOW,
  CHIP_SHIPPED,
  HIT_FILTER_ALL,
  HIT_FILTER_LIVE,
  HIT_FILTER_SHADOW,
  HIT_FILTER_UNREAD,
  HIT_GROUP_APPROVE,
  HIT_GROUP_FOLD,
  HIT_GROUP_REJECT,
  UNREAD_DOT,
  chipRead,
  hitGroupMarkRead,
} from '../lib/tooltips';
import { useAsync } from '../lib/useAsync';
import { AnalyticDrawer } from './AnalyticDrawer';
import { DISMISS_REASONS, REASON_LABEL, benignLine } from './LeadsStrip';
import { Definition } from './Definition';
import { DocumentChip } from './DocumentDrawer';
import { CollapseChevron, Panel } from './Panel';
import { LoadingInline, StaleNotice } from './States';

// ---------------------------------------------------------------------------
// Analytic hits — every hit an analytic wrote in the last 7 days, live and
// shadow, in one list.
//
// A hit is an observation an analytic wrote. The old band held the shadow hits
// alone, so the real signal had no surface and a shadow hit read as the only
// thing the analytics produce. The unread shadow hits come first here: Needs-you
// counts them, and 147 live hits ahead of one unread shadow hit pushed it off
// the first page of 50. The live hits follow, newest first, then the read
// shadow hits.
//
// The list reads 50 hits a page. The line under it states how many of the
// window's hits it holds, and "Show more" reads the next page.
//
// The hits are grouped by analytic (review 2026-11-12, F2). The header of a
// group is the analytic: the logic, its status, its counts over the whole
// list, and the decisions on it, once. A card under the header is the hit:
// the instance the analytic wrote. 233 unread hits of 3 analytics repeated
// the two decisions on 233 cards, and the pile took 233 presses to read.
//
// The owner's rule: the real hit is never lighter than the provisional one. A
// live hit carries a solid accent border, and the title of a live analytic is
// bold. A shadow hit carries a dashed amber border. A read shadow hit is
// dimmer still.
//
// A hit whose receipts are incomplete reads "could not run" and names the
// missing part. It is never shown as a hit and it is never hidden.
// ---------------------------------------------------------------------------

const AMBER = '#d29922';

/** The block the chevron folds. The anchor `analytic-hits` stays on the panel,
 *  so a link still reaches the header of a folded section. */
const BODY_ID = 'analytic-hits-body';

const SECTION_NOTE =
  'What the analytics found. Unread shadow hits come first, then live hits, then read shadow hits.';

/** The hits one request reads. "Show more" reads one more page of this size. */
export const HITS_PAGE = 50;

/** The days the block covers. The request and the label read this one number. */
export const HITS_WINDOW_DAYS = 7;

/** The label beside the heading: the two parts of the list, each with its
 *  own window.
 *
 *  The label read "last 7 days · 249" over 39 hits from those days and 210
 *  older unread shadow hits (review 2026-11-12, F3). A count obeys the window
 *  on its label, or it states its own window. A server that sends one total
 *  gets both windows in words. */
export function hitsWindowLabel(
  all: number,
  window: { days: number; in_window: number; older_unread: number } | null | undefined,
): string {
  if (!window) return `last ${HITS_WINDOW_DAYS} days and older unread · ${all}`;
  return `${window.in_window} in the last ${window.days} days · ${window.older_unread} older unread`;
}

const SHOW_MORE_TOOLTIP = `Read the next ${HITS_PAGE} hits of this list.`;

/** Read the first `pages` pages of one filter as one list.
 *
 *  Every poll reads every page the analyst has opened. A page read once and
 *  kept lost a hit: a new hit moves each row down by one, and the row at the
 *  page edge left page 1 without a reach into page 2. A hit that two pages
 *  both hold is listed once. */
async function readHitPages(
  filter: AnalyticHitFilter,
  pages: number,
): Promise<AnalyticHitsPage> {
  const answers = await Promise.all(
    Array.from({ length: pages }, (_, n) =>
      getAnalyticHits({ days: HITS_WINDOW_DAYS, filter, limit: HITS_PAGE, offset: n * HITS_PAGE }),
    ),
  );
  const seen = new Set<number>();
  const hits = answers
    .flatMap((a) => a.hits)
    .filter((h) => {
      if (seen.has(h.id)) return false;
      seen.add(h.id);
      return true;
    });
  return {
    hits,
    counts: answers[0].counts,
    window: answers[0].window,
    groups: answers[0].groups,
  };
}

const TITLE_TOOLTIP = 'Open the analytic: its definition, its ledger and its versions.';

const FILTERS: { id: AnalyticHitFilter; label: string; title: string }[] = [
  { id: 'all', label: 'All', title: HIT_FILTER_ALL },
  { id: 'unread', label: 'Unread', title: HIT_FILTER_UNREAD },
  { id: 'live', label: 'Live', title: HIT_FILTER_LIVE },
  { id: 'shadow', label: 'Shadow', title: HIT_FILTER_SHADOW },
];

/** What an empty hit list means. "No analytic matched a document the sweeps
 *  read" was a false all-clear on a grid where no sweep had run.
 *
 *  A loop whose last run failed, and a profile sweep that measured no host,
 *  found nothing because it read nothing. "The profile analytics found
 *  nothing." over a dead grid was the same false all-clear (dogfood
 *  2026-10-19 H1-D2). */
export function emptyHitsText(catalog: HuntCatalog | null | undefined): string {
  const head = 'No analytic hit in the last 7 days.';
  if (!catalog) return `${head} soc-ai cannot tell if the sweeps ran.`;
  const match = loopRuns(catalog, 'match');
  const profile = loopRuns(catalog, 'profile');
  const matchFailed = match !== false && catalog.sweep_health?.last_outcome === 'failed';
  const priorHealth = catalog.prior_sweep_health;
  const profileFailed =
    catalog.prior_sweeps_enabled !== false && !!priorHealth && priorHealth.last_outcome !== 'ok';
  const profiled = catalog.specs.filter(
    (s) => runsInProfileSweep(s.evaluator) && s.status !== 'retired' && s.coverage,
  );
  const profileUnmeasured =
    !!profile &&
    !profileFailed &&
    profiled.length > 0 &&
    profiled.every((s) => s.coverage && evaluations(s.coverage) === 0);
  if (match && profile !== false && !matchFailed && !profileFailed && !profileUnmeasured) {
    return `${head} No analytic matched a document the sweeps read.`;
  }
  const parts = [head];
  if (!match) {
    parts.push(
      catalog.sweeps_enabled
        ? 'No analytic sweep has run yet.'
        : 'Sweeps are off. The match analytics do not run.',
    );
  }
  if (profile === false && !profileFailed) {
    parts.push(
      catalog.prior_sweeps_enabled === false
        ? 'The profile sweep is off. The profile analytics do not run.'
        : 'The profile sweep has not run yet.',
    );
  }
  if (matchFailed) parts.push('The last analytic sweep could not read the grid.');
  else if (match) parts.push('The match analytics found nothing.');
  if (profileFailed) parts.push('The last profile sweep could not read the grid.');
  else if (profileUnmeasured) parts.push('The profile analytics measured no host.');
  else if (profile) parts.push('The profile analytics found nothing.');
  return parts.join(' ');
}

const isFilter = (v: unknown): v is AnalyticHitFilter => FILTERS.some((f) => f.id === v);

/** The objective a hunt from this card runs under.
 *
 *  The analytic writes its own title into the summary, so the objective named
 *  the analytic twice and the agent read the second one as a second subject.
 *  The title is stated once. */
export function huntObjective(hit: AnalyticHit): string {
  const noun = hit.analytic_status === 'shadow' ? 'shadow analytic' : 'analytic';
  return `Investigate ${hit.entity_key}. The ${noun} "${hit.analytic_title}" matched it. ${
    summaryBody(hit) ?? ''
  }`.trim();
}

/** The summary, less the analytic title it repeats. The card states the title
 *  on the line above, so a summary that only repeats it adds no fact. */
function summaryBody(hit: AnalyticHit): string | null {
  const summary = (hit.summary ?? '').trim();
  if (!summary) return null;
  const body = summary.startsWith(hit.analytic_title)
    ? summary.slice(hit.analytic_title.length).replace(/^[\s:.·-]+/, '')
    : summary;
  // The sweep writes "<entity> (<n> documents)". The hit line already says
  // both, so that body adds no fact either.
  const entityAndCount = new RegExp(
    `^${hit.entity_key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\(\\d+ documents?\\)\\.?$`,
  );
  if (!body || entityAndCount.test(body)) return null;
  return body;
}

/** The dry-run fact as one sentence, for the summary line.
 *
 *  The card's two lines name the analytic and the instance. The dry run is the
 *  one fact neither carries, and it sat behind Show evidence, so no card on the
 *  range showed a summary line at all. A shadow hit adds what the overlap says:
 *  an empty overlap means no live analytic read the same documents, which is
 *  the reason the hit is worth reading. A live hit makes no such claim: its own
 *  analytic read them. */
function dryRunLine(hit: AnalyticHit): string | null {
  const dry = hit.receipts?.dry_run;
  if (!dry) return null;
  // The flag on the row, not the status now. The receipts are what the sweep
  // wrote when it recorded the hit, and the overlap is a fact about that run.
  const shadow = hit.recorded_in_shadow;
  const alone =
    shadow && (hit.receipts?.overlap ?? []).length === 0
      ? ' No live analytic read these documents.'
      : '';
  return (
    `The ${dry.window_days} day dry run would have fired ${plural(dry.fires, 'time')} on ` +
    `${entityNoun(hit.entity_kind, dry.entities.length)}.${alone}`
  );
}

/** The parts of the receipts that are absent. The hit names them, and a packet
 *  that carries its own list names them too. One of the two always answers. */
function missingText(hit: AnalyticHit): string {
  const missing = (hit.missing?.length ? hit.missing : hit.receipts?.missing) ?? [];
  return missing.length ? missing.map((m) => m.replace(/_/g, ' ')).join(', ') : 'the evidence';
}

/** The note beside the lead link, in the lead's own state.
 *
 *  The card read "Decide there" over a lead an analyst had promoted the day
 *  before. The decision was made, and the card sent the analyst to make it
 *  again. A status the four words do not name keeps the open sentence: the lead
 *  is the place to decide, whatever else it is. */
function leadNote(status: string | null): string {
  if (status === 'dismissed') return 'The lead that held this hit was dismissed.';
  if (status === 'promoted') return 'The lead that held this hit was promoted.';
  return 'The lead holds this hit. Decide there.';
}

/** The noun for one entity kind. A dry run over user accounts counted hosts,
 *  and "2 hosts" is a false statement about two accounts. */
function entityNoun(kind: string, n: number): string {
  if (kind === 'user') return plural(n, 'user');
  if (kind === 'ip') return plural(n, 'IP address', 'IP addresses');
  return plural(n, 'host');
}

function keyPath(kind: string, key: string): string {
  return pathOfEntity(kind, key);
}

/** The documents a hit counts: the receipts of a shadow hit, else the ids
 *  the server stores on the row. W2: a live hit carries no receipts, so
 *  "Show evidence" read "No evidence." over a row that counted three
 *  documents. */
export function hitDocumentIds(hit: AnalyticHit): string[] {
  const matched = hit.receipts?.matched_ids ?? [];
  return matched.length > 0 ? matched : (hit.document_ids ?? []);
}

/** The title of an analytic the catalog no longer lists. The sweep wrote the
 *  title at the head of the summary: "<title>: <entity> (n documents)". A
 *  summary in another shape leaves the id in words. C7: the card showed the
 *  slug "prior-defender-adjudication-on-server". */
export function removedAnalyticTitle(hit: AnalyticHit): string {
  const summary = (hit.summary ?? '').trim();
  const cut = summary.indexOf(`: ${hit.entity_key}`);
  if (cut > 0) return summary.slice(0, cut);
  const words = hit.analytic_id.replace(/[-_]+/g, ' ').trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : hit.analytic_id;
}

/** The reason form for "Mark benign". It opens with no reason chosen, and it
 *  offers the reasons a lead dismissal offers, so the sharpening loop reads
 *  one list. */
function BenignForm({
  hitId,
  onDone,
  onCancel,
}: {
  hitId: number;
  onDone: () => void;
  onCancel: () => void;
}) {
  const [reason, setReason] = useState('');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  const selectId = `benign-reason-${hitId}`;
  const confirm = async () => {
    setBusy(true);
    setFailed(null);
    try {
      await markObservationBenign(hitId, reason, note || undefined);
      onDone();
    } catch (e) {
      setFailed(e instanceof Error && e.message ? e.message : 'The hit was not marked benign.');
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="col-span-2 flex flex-wrap items-center gap-2 text-[12px]" data-testid="benign-form">
      <span className="basis-full text-[11.5px] text-dim">
        The hit is marked benign with this reason. It counts toward no lead.
      </span>
      <label htmlFor={selectId}>Reason</label>
      <select
        id={selectId}
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        className="rounded-control border border-border bg-surface-2 px-2 py-1"
      >
        <option value="">Choose a reason</option>
        {DISMISS_REASONS.map((r) => (
          <option key={r} value={r}>
            {REASON_LABEL[r] ?? r}
          </option>
        ))}
      </select>
      <input
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="Note, optional"
        className="min-w-[200px] flex-1 rounded-control border border-border bg-surface-2 px-2 py-1"
      />
      <button
        type="button"
        disabled={!reason || busy}
        onClick={() => void confirm()}
        className="rounded-control bg-accent px-3 py-1 font-semibold text-white disabled:opacity-50"
      >
        Confirm benign
      </button>
      <button type="button" onClick={onCancel} className="text-dim">
        Cancel
      </button>
      {failed && <span className="basis-full text-[11.5px] text-danger">{failed}</span>}
    </div>
  );
}

/** One labelled group inside the evidence panel. The panel was three
 *  unlabelled lines, so an analyst could not tell the dry run from the
 *  overlap. */
function Group({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="mt-2 first:mt-0">
      <div className="text-faint">{label}</div>
      <div className="mt-1 flex flex-wrap items-center gap-1.5">{children}</div>
    </div>
  );
}

/**
 * The evidence of one hit, in four labelled groups.
 *
 * The receipts are the proof the analytic works, so every part of them is a
 * destination. A document opens in the drawer, an entity reaches its page and
 * an overlapping analytic reaches its drawer on the Analytics tab.
 */
function Evidence({ hit }: { hit: AnalyticHit }) {
  const r = hit.receipts;
  const ids = hitDocumentIds(hit);
  const dry = r?.dry_run;
  const entities = dry?.entities ?? [];
  const overlap = r?.overlap ?? [];
  return (
    <div
      data-testid="analytic-hit-evidence"
      className="col-span-2 mt-2 rounded-panel border border-border bg-surface-1 p-3 text-[11.5px]"
    >
      <Group label="Matched documents">
        {ids.length === 0 ? (
          <span className="text-dim">No document id.</span>
        ) : (
          ids.map((id) => <DocumentChip key={id} id={id} />)
        )}
      </Group>
      {dry && (
        <Group label={`Dry run over ${dry.window_days} days`}>
          <span className="text-dim">
            It fired {plural(dry.fires, 'time')} on {entityNoun(hit.entity_kind, entities.length)}.
          </span>
          {entities.map((e) => (
            <Link
              key={e}
              to={keyPath(hit.entity_kind, e)}
              className="rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px font-mono text-accent hover:underline"
            >
              {e}
            </Link>
          ))}
        </Group>
      )}
      {overlap.length > 0 && (
        <Group label="Overlap">
          {overlap.map((o) => (
            <Link
              key={o.analytic}
              to={`/hunts?tab=analytics&open=${encodeURIComponent(o.analytic)}`}
              title="A live analytic observed these documents. Open it to read what it does."
              className="rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px font-mono text-accent hover:underline"
            >
              {o.analytic} · {plural(o.documents, 'document')}
            </Link>
          ))}
        </Group>
      )}
      {r?.baseline && (
        <Group label="Baseline">
          <span className="whitespace-pre-wrap break-all font-mono text-dim">
            {JSON.stringify(r.baseline)}
          </span>
        </Group>
      )}
    </div>
  );
}

/** One chip on the analytic line or the hit line. */
function Chip({
  label,
  title,
  tone,
}: {
  label: string;
  title: string;
  tone?: 'live' | 'shadow' | 'faint';
}) {
  const style =
    tone === 'shadow'
      ? { color: AMBER, borderColor: 'rgba(210,153,34,.35)' }
      : tone === 'live'
        ? { color: '#3fb950', borderColor: 'rgba(63,185,80,.35)' }
        : undefined;
  return (
    <span
      title={title}
      style={style}
      className={`flex-none rounded-chip border px-1.5 py-px text-[10.5px] ${
        tone === 'faint' ? 'border-border-faint text-faint' : 'border-border-strong text-dim'
      }`}
    >
      {label}
    </span>
  );
}

function HitCard({
  hit,
  read,
  onRead,
  onChange,
}: {
  hit: AnalyticHit;
  /** True once the analyst has read it, from the server or from this session.
   *  The block holds the session part, so the list does not reorder under the
   *  hand that is working it. */
  read: boolean;
  onRead: (id: number) => void;
  onChange: () => void;
}) {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [markingBenign, setMarkingBenign] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);

  // Two facts, and the card read one of them as both. The status is the
  // analytic today: it carries the chip and the two decisions. The flag says
  // where the hit was recorded: it picks the half, the border, the weight and
  // the read state, and it holds until the sweep writes the row again.
  // A hit whose analytic the catalog no longer lists. The status the server
  // sends for it is the flag on the row, so the card read "live" on an
  // analytic that does not exist. An older server sends no flag.
  const removed = hit.analytic_exists === false;
  const liveAnalytic = !removed && hit.analytic_status === 'live';
  const shadowAnalytic = !removed && hit.analytic_status === 'shadow';
  const recordedLive = !hit.recorded_in_shadow;
  // `complete` false is the packet's own verdict on itself. A shadow hit must
  // prove itself, so the state word and the flag must agree before the card
  // claims a hit. A live hit has already been approved, and a packet without
  // receipts is not a reason to call its hit unproven.
  const provable = hit.state === 'hit' && (recordedLive || (hit.receipts?.complete ?? false));
  const unread = !recordedLive && !read;
  // An analyst marked the hit benign. It counts toward no lead.
  const benign = Boolean(hit.dismissed_at);

  // A shadow hit is unread until the analyst opens its evidence or acts on it.
  // Every path calls this, so an analyst who hunts the entity without reading
  // the evidence does not leave the hit unread for another day.
  //
  // A read does not fetch the list again. The server answers unread first, so a
  // refetch here moves the card out from under the analyst who has just opened
  // its evidence. The block holds the read ids until the next load.
  const markRead = async () => {
    if (recordedLive || read) return;
    setFailed(null);
    try {
      await markShadowHitRead(hit.id);
      onRead(hit.id);
    } catch {
      setFailed('The hit was not marked read. Try again.');
    }
  };

  const toggleEvidence = async () => {
    setOpen((v) => !v);
    await markRead();
  };

  const hunt = async () => {
    setBusy(true);
    setFailed(null);
    try {
      await markRead();
      const started = await startHuntConsole(huntObjective(hit));
      navigate(`/hunts/${started.hunt_id}`);
    } catch {
      setFailed('The hunt did not start. Try again.');
    } finally {
      setBusy(false);
    }
  };

  // The stored summary first: the analytic wrote it about this instance. When
  // it repeats the two lines above it, the dry run is the fact that does not.
  const summary = summaryBody(hit) ?? dryRunLine(hit);
  // The panel has something to show: receipts, or the ids of the documents.
  const hasEvidence = Boolean(hit.receipts) || hitDocumentIds(hit).length > 0;
  const when = hit.first_seen_at ?? hit.born_at;

  return (
    <li
      data-testid={`analytic-hit-${hit.id}`}
      data-hit-status={recordedLive ? 'live' : 'shadow'}
      data-read={recordedLive ? undefined : read ? 'true' : 'false'}
      className={`grid grid-cols-[1fr_auto] gap-x-4 gap-y-1.5 border-t border-border-faint px-[15px] py-3 ${
        !recordedLive && read ? 'opacity-70' : ''
      }`}
      style={
        recordedLive
          ? { borderLeft: '3px solid #4b8bf5', background: 'rgba(75,139,245,.05)' }
          : { borderLeft: '3px dashed rgba(210,153,34,.6)' }
      }
    >
      <div className="min-w-0">
        {/* The header of the group names the analytic, its status and its
            tier once. The card states the hit, and the chips that are about
            this hit alone. */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
            Hit:
          </span>
          {unread && (
            <span
              className="h-[7px] w-[7px] flex-none rounded-full"
              style={{ background: AMBER, boxShadow: '0 0 0 3px rgba(210,153,34,.25)' }}
              title={UNREAD_DOT}
            />
          )}
          <Link
            to={keyPath(hit.entity_kind, hit.entity_key)}
            className="font-mono text-[12.5px] font-semibold text-accent hover:underline"
          >
            {hit.entity_key}
          </Link>
          <span className="text-[11px] text-dim">{plural(hit.document_count, 'document')}</span>
          {/* `born_at` moves with the newest sighting, so the card read an
              observation a week old as 20 minutes old. */}
          <span
            data-testid="analytic-hit-time"
            className="font-mono text-[11px] text-dim"
            title={absTime(when)}
          >
            first seen {ago(when)}
          </span>
          <span className="font-mono text-[11px] text-dim">
            seen {plural(hit.occurrences ?? 1, 'time')}
          </span>
          {hit.lead_id !== null ? (
            <>
              <span className="text-faint">·</span>
              <Link
                to={`/leads/${hit.lead_id}`}
                className="text-[11.5px] text-accent hover:underline"
              >
                Lead {hit.lead_id}
              </Link>
            </>
          ) : (
            <Chip label="no lead" title={hit.no_lead_reason ?? CHIP_NO_LEAD} tone="faint" />
          )}
          {/* The hit lists under Shadow and its analytic reads live. The chip
              states why, so the two words do not read as a contradiction. */}
          {!recordedLive && liveAnalytic && (
            <Chip label="recorded in shadow" title={CHIP_RECORDED_IN_SHADOW} tone="faint" />
          )}
          {/* The other way round: the hit lists under Live and its analytic
              reads shadow, because soc-ai or an analyst moved it after the hit
              (R3-D11). */}
          {recordedLive && shadowAnalytic && (
            <Chip label="recorded live" title={CHIP_RECORDED_LIVE} tone="faint" />
          )}
          {!recordedLive && read && (
            <Chip
              label={hit.read_at ? `read ${ago(hit.read_at)}` : 'read'}
              title={chipRead(hit.read_at ? ago(hit.read_at) : null)}
              tone="faint"
            />
          )}
          {!provable && (
            <Chip
              label="could not run"
              title="The evidence of this hit is incomplete. Read the missing part below."
            />
          )}
        </div>

        {summary && (
          <div data-testid="analytic-hit-summary" className="mt-1.5 text-[12.5px] text-text-2">
            {summary}
          </div>
        )}
        {recordedLive && shadowAnalytic && hit.analytic_held_by_system && (
          <div data-testid="analytic-hit-held" className="mt-1.5 text-[11.5px] text-warn">
            {`soc-ai held this analytic in shadow after this hit. ${hit.analytic_held_by_system} ` +
              'The hit counts toward a lead. Approve or reject the analytic.'}
          </div>
        )}
        {benign && (
          <div data-testid="analytic-hit-benign" className="mt-1.5 text-[11.5px] text-dim">
            {benignLine(hit)}
          </div>
        )}
        {!provable && (
          <div className="mt-1.5 text-[11.5px] leading-[1.6] text-dim">
            {`The evidence is incomplete. Missing: ${missingText(hit)}. This analytic did not ` +
              'prove its hit. This is not an all-clear.'}
          </div>
        )}

        <div className="mt-2 flex flex-wrap items-center gap-2">
          {hasEvidence ? (
            <>
              <button
                type="button"
                onClick={toggleEvidence}
                className="rounded-control border border-border-strong px-3 py-1 text-[11.5px] font-semibold"
              >
                {open ? 'Hide evidence' : 'Show evidence'}
              </button>
              <span className="text-[11px] text-dim">
                {plural(hitDocumentIds(hit).length || hit.document_count, 'document id')}
              </span>
            </>
          ) : (
            // No id is stored, so a button would open an empty panel. The
            // lead holds the documents when one holds the hit.
            <span data-testid="analytic-hit-no-ids" className="text-[11.5px] text-dim">
              {hit.lead_id !== null
                ? `Open lead ${hit.lead_id} to read the documents.`
                : 'soc-ai stored no document id for this hit.'}
            </span>
          )}
        </div>
        {failed && <div className="mt-1.5 text-[11.5px] text-warn">{failed}</div>}
      </div>

      <div className="flex flex-col items-stretch gap-1.5 self-start">
        {hit.lead_id !== null ? (
          <>
            {/* The lead is where the decision is made, so a hit never starts a
                second hunt beside it. The lead has a page, so this is a link. */}
            <Link
              to={`/leads/${hit.lead_id}`}
              className="rounded-control px-3 py-1 text-center text-[12px] font-semibold text-accent underline hover:opacity-80"
            >
              Open lead {hit.lead_id}
            </Link>
            <span className="max-w-[150px] text-[11px] text-faint">
              {leadNote(hit.lead_status)}
            </span>
          </>
        ) : (
          <>
            <button
              type="button"
              disabled={busy}
              onClick={hunt}
              className="rounded-control bg-accent px-3 py-1 text-[11.5px] font-semibold text-white disabled:opacity-50"
            >
              Hunt this entity
            </button>
            {/* C7: a live hit the analyst reads as benign. The only act was
                a hunt, and five Windows updates each asked for one. */}
            {recordedLive && !benign && (
              <button
                type="button"
                disabled={busy}
                onClick={() => setMarkingBenign((v) => !v)}
                className="rounded-control border border-border-strong px-3 py-1 text-[11.5px] font-semibold disabled:opacity-50"
              >
                Mark benign
              </button>
            )}
          </>
        )}
        {/* The read action an analyst can take without a decision. A hit that
            is understood from the summary alone had no way off the unread count
            except an action the analyst did not want to take. */}
        {unread && (
          <button
            type="button"
            onClick={markRead}
            className="px-3 text-[11px] text-dim hover:underline"
          >
            Mark read
          </button>
        )}
      </div>

      {open && hasEvidence && <Evidence hit={hit} />}
      {markingBenign && (
        <BenignForm
          hitId={hit.id}
          onCancel={() => setMarkingBenign(false)}
          onDone={() => {
            setMarkingBenign(false);
            onChange();
          }}
        />
      )}
    </li>
  );
}

/** The hits of a group the block shows before the analyst unfolds it. */
export const GROUP_PREVIEW = 3;

/** One analytic of the block: its counts, and the hits of it the list has read. */
export interface HitGroup {
  id: string;
  title: string;
  status: string;
  tier: string;
  exists: boolean;
  hits: number;
  unread: number;
  machines: number;
  accounts: number;
  /** True when the server counted the group over the whole list. False when
   *  the block counted the hits it has read, for a server that sends no group. */
  counted: boolean;
  rows: AnalyticHit[];
}

/** An analytic id in words, for a group whose analytic the catalog lost and
 *  whose hits the list has not read. */
function idInWords(id: string): string {
  const words = id.replace(/[-_]+/g, ' ').trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : id;
}

/** The hits of the list, grouped by analytic, in the order of the server.
 *
 *  The server counts each group over the whole list. A hit that this session
 *  read comes off the unread count of its group, by the rule of the unread
 *  chip. A hit whose analytic the server named no group for gets a group that
 *  counts the hits the list has read. */
export function groupHits(
  rows: readonly AnalyticHit[],
  served: readonly AnalyticHitGroup[] | undefined,
  readIds: ReadonlySet<number>,
): HitGroup[] {
  const byAnalytic = new Map<string, AnalyticHit[]>();
  for (const row of rows) {
    const mine = byAnalytic.get(row.analytic_id);
    if (mine) mine.push(row);
    else byAnalytic.set(row.analytic_id, [row]);
  }
  const out: HitGroup[] = [];
  const seen = new Set<string>();
  for (const g of served ?? []) {
    seen.add(g.analytic_id);
    const mine = byAnalytic.get(g.analytic_id) ?? [];
    const readHere = mine.filter(
      (h) => h.recorded_in_shadow && h.read === false && readIds.has(h.id),
    ).length;
    out.push({
      id: g.analytic_id,
      title: g.analytic_exists
        ? g.analytic_title
        : mine[0]
          ? removedAnalyticTitle(mine[0])
          : idInWords(g.analytic_id),
      status: g.analytic_status,
      tier: g.tier,
      exists: g.analytic_exists,
      hits: Math.max(g.hits, mine.length),
      unread: Math.max(0, g.unread - readHere),
      machines: g.machines,
      accounts: g.accounts,
      counted: true,
      rows: mine,
    });
  }
  for (const [id, mine] of byAnalytic) {
    if (seen.has(id)) continue;
    const first = mine[0];
    const exists = first.analytic_exists !== false;
    const keys = (user: boolean) =>
      new Set(mine.filter((h) => (h.entity_kind === 'user') === user).map((h) => h.entity_key)).size;
    out.push({
      id,
      title: exists ? first.analytic_title : removedAnalyticTitle(first),
      status: first.analytic_status,
      tier: first.tier,
      exists,
      hits: mine.length,
      unread: mine.filter((h) => h.recorded_in_shadow && h.read !== true && !readIds.has(h.id))
        .length,
      machines: keys(false),
      accounts: keys(true),
      counted: false,
      rows: mine,
    });
  }
  return out;
}

/** "116 hits · 116 unread · 44 machines". The unread part is for an analytic
 *  in shadow, and for any analytic that still holds an unread hit. */
function groupCountsText(group: HitGroup): string {
  const parts = [plural(group.hits, 'hit')];
  if (group.status === 'shadow' || group.unread > 0) parts.push(`${group.unread} unread`);
  if (group.machines > 0 || group.accounts === 0) parts.push(plural(group.machines, 'machine'));
  if (group.accounts > 0) parts.push(plural(group.accounts, 'account'));
  return parts.join(' · ');
}

/**
 * One analytic and its hits.
 *
 * The header carries the decisions on the analytic once: Approve, Reject and
 * "Mark N read". Each button states its effect in one line under the counts
 * and on its hover. The rows fold under the header: three hits are in view,
 * and the rest of the hits the list has read open on request.
 */
function HitGroupBlock({
  group,
  loadedAt,
  wasRead,
  onRead,
  onChange,
  onOpenAnalytic,
}: {
  group: HitGroup;
  /** When the block loaded its counts. A bulk read takes the hits up to it. */
  loadedAt: number | null;
  wasRead: (hit: AnalyticHit) => boolean;
  onRead: (id: number) => void;
  onChange: () => void;
  onOpenAnalytic: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [approving, setApproving] = useState(false);
  const [rejecting, setRejecting] = useState(false);
  const [why, setWhy] = useState('');
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);

  const liveAnalytic = group.exists && group.status === 'live';
  const shadowAnalytic = group.exists && group.status === 'shadow';
  // A shadow hit must prove itself before the analytic can go live on it. The
  // header offers the approval when a hit the list has read proves itself.
  const provable = group.rows.some(
    (h) => h.state === 'hit' && (!h.recorded_in_shadow || (h.receipts?.complete ?? false)),
  );
  const canApprove = shadowAnalytic && provable;
  const canReject = shadowAnalytic;
  const canMarkRead = group.unread > 0;
  const effects = [
    canApprove ? HIT_GROUP_APPROVE : null,
    canReject ? HIT_GROUP_REJECT : null,
    canMarkRead ? hitGroupMarkRead(group.unread) : null,
  ].filter((line): line is string => line !== null);

  const refusal = (e: unknown, fallback: string) =>
    e instanceof ApiError && e.reason ? e.message : e instanceof Error && e.message ? e.message : fallback;

  // One write for the unread hits of this analytic. The count on the button
  // goes with it, so the server marks nothing when more hits arrived.
  const markAllRead = async () => {
    setBusy(true);
    setFailed(null);
    try {
      await markAnalyticShadowHitsRead(
        group.id,
        new Date(loadedAt ?? Date.now()).toISOString(),
        group.counted ? group.unread : undefined,
      );
      onChange();
    } catch (e) {
      setFailed(refusal(e, 'The hits were not marked read. Try again.'));
    } finally {
      setBusy(false);
    }
  };

  // The decision is what reads the hits. The server names the statuses one
  // status can move to, and that sentence is the answer to a refusal.
  const decide = async (to: 'live' | 'retired') => {
    setBusy(true);
    setFailed(null);
    try {
      await setAnalyticStatus(group.id, to, why);
      setApproving(false);
      setRejecting(false);
      setWhy('');
      // A retirement takes the hits off the list. An approval leaves them on
      // the shadow half, so the decision reads them.
      if (to === 'live' && group.unread > 0) {
        try {
          await markAnalyticShadowHitsRead(group.id, new Date().toISOString());
        } catch {
          setFailed('The analytic is live. Its hits were not marked read. Try Mark read again.');
        }
      }
      onChange();
    } catch (e) {
      setFailed(refusal(e, 'The status did not change. Try again.'));
    } finally {
      setBusy(false);
    }
  };

  const shown = open ? group.rows : group.rows.slice(0, GROUP_PREVIEW);
  const folded = group.rows.length - GROUP_PREVIEW;
  const decisionClass =
    'rounded-control border px-3 py-1 text-[11.5px] font-semibold disabled:opacity-50';

  return (
    <section
      data-testid={`analytic-group-${group.id}`}
      aria-label={`Analytic: ${group.title}`}
      className="border-t border-border"
    >
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 bg-surface-2/40 px-[15px] py-2.5">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
              Analytic:
            </span>
            {group.exists ? (
              <button
                type="button"
                data-testid="analytic-group-title"
                className={`text-left text-[13px] hover:underline ${
                  liveAnalytic ? 'font-bold' : 'font-medium'
                }`}
                title={TITLE_TOOLTIP}
                onClick={() => onOpenAnalytic(group.id)}
              >
                {group.title}
              </button>
            ) : (
              // No drawer can open an analytic the catalog does not list, so
              // the id is text and not a control.
              <span
                data-testid="analytic-group-title"
                className="text-[13px] text-dim"
                title={`Analytic ${group.id}`}
              >
                {group.title}
              </span>
            )}
            {group.exists ? (
              <Chip
                label={group.status}
                title={liveAnalytic ? CHIP_LIVE : CHIP_SHADOW}
                tone={liveAnalytic ? 'live' : 'shadow'}
              />
            ) : (
              <Chip label="analytic removed" title={CHIP_ANALYTIC_REMOVED} tone="faint" />
            )}
            <Chip
              label={group.tier === 'shipped' ? 'shipped' : 'local'}
              title={group.tier === 'shipped' ? CHIP_SHIPPED : CHIP_LOCAL}
            />
          </div>
          <div
            data-testid="analytic-group-counts"
            className="mt-1 font-mono text-[11.5px] tabular-nums text-dim"
            title={HIT_GROUP_FOLD}
          >
            {groupCountsText(group)}
          </div>
          {effects.length > 0 && (
            <div data-testid="analytic-group-effects" className="mt-1 text-[11.5px] leading-[1.5] text-faint">
              {effects.join(' ')}
            </div>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {canApprove && (
            <button
              type="button"
              disabled={busy}
              title={HIT_GROUP_APPROVE}
              onClick={() => {
                setApproving(true);
                setRejecting(false);
              }}
              className={decisionClass}
              style={{ color: AMBER, borderColor: 'rgba(210,153,34,.5)' }}
            >
              Approve analytic
            </button>
          )}
          {canReject && (
            <button
              type="button"
              disabled={busy}
              title={HIT_GROUP_REJECT}
              onClick={() => {
                setRejecting(true);
                setApproving(false);
              }}
              className={`${decisionClass} border-border-strong text-dim`}
            >
              Reject analytic
            </button>
          )}
          {canMarkRead && (
            <button
              type="button"
              disabled={busy}
              title={hitGroupMarkRead(group.unread)}
              onClick={() => void markAllRead()}
              className={`${decisionClass} border-border-strong`}
            >
              {`Mark ${group.unread.toLocaleString()} read`}
            </button>
          )}
        </div>
        {(approving || rejecting) && (
          <div className="flex basis-full flex-wrap items-center gap-2 text-[12px]">
            {/* "Reject" named no outcome. The analytic is retired, it stops
                running, and the reason is stored on the transition. */}
            <span data-testid="analytic-decision-note" className="basis-full text-[11.5px] text-dim">
              {approving
                ? `The analytic goes live with this reason. It raises what it finds.${
                    group.unread > 0
                      ? ` Its ${plural(group.unread, 'unread hit')} ${
                          group.unread === 1 ? 'is' : 'are'
                        } marked read.`
                      : ''
                  }`
                : 'The analytic is retired with this reason. It stops running. Its hits leave this list.'}
            </span>
            <input
              value={why}
              onChange={(e) => setWhy(e.target.value)}
              placeholder={approving ? 'Why it goes live' : 'Why it is rejected'}
              className="min-w-[260px] flex-1 rounded-control border border-border bg-surface-2 px-2 py-1"
            />
            <button
              type="button"
              disabled={!why || busy}
              onClick={() => void decide(approving ? 'live' : 'retired')}
              className="rounded-control bg-accent px-3 py-1 font-semibold text-white disabled:opacity-50"
            >
              Confirm
            </button>
            <button
              type="button"
              onClick={() => {
                setApproving(false);
                setRejecting(false);
              }}
              className="text-dim"
            >
              Cancel
            </button>
          </div>
        )}
        {failed && (
          <div data-testid="analytic-group-failed" className="basis-full text-[11.5px] text-warn">
            {failed}
          </div>
        )}
      </div>
      {shown.length > 0 && (
        <ul>
          {shown.map((hit) => (
            <HitCard key={hit.id} hit={hit} read={wasRead(hit)} onRead={onRead} onChange={onChange} />
          ))}
        </ul>
      )}
      {(folded > 0 || (group.counted && group.rows.length < group.hits)) && (
        <div className="flex flex-wrap items-center gap-3 border-t border-border-faint px-[15px] py-2 text-[11.5px] text-dim">
          {folded > 0 && (
            <button
              type="button"
              data-testid="analytic-group-toggle"
              aria-expanded={open}
              onClick={() => setOpen((v) => !v)}
              className="font-semibold text-accent hover:underline"
            >
              {open ? 'Show fewer hits' : `Show ${plural(folded, 'more hit')}`}
            </button>
          )}
          {group.counted && group.rows.length < group.hits && (
            <span data-testid="analytic-group-share">
              {`The list holds ${group.rows.length} of the ${plural(group.hits, 'hit')} of this analytic. ` +
                'Show more reads the next hits of the list.'}
            </span>
          )}
        </div>
      )}
    </section>
  );
}

export function AnalyticHits({
  onAnalyticChanged,
  collapsed = false,
  onToggleCollapsed,
}: {
  onAnalyticChanged?: () => void;
  /** The fold of the section. The page holds it, because a Needs-you link has
   *  to open this block before it scrolls to it. */
  collapsed?: boolean;
  /** When the page passes this, the header carries the chevron. */
  onToggleCollapsed?: () => void;
} = {}) {
  const [params, setParams] = useSearchParams();
  const wanted = params.get('hits');
  const filter: AnalyticHitFilter = isFilter(wanted) ? wanted : 'all';
  const [reload, setReload] = useState(0);
  // The hits an analyst has read in this session. The server answers unread
  // first, so a refetch on every read reordered the list under the hand that
  // was working it. The order holds until the next load.
  const [readIds, setReadIds] = useState<ReadonlySet<number>>(() => new Set<number>());
  const [openAnalytic, setOpenAnalytic] = useState<string | null>(null);
  // The pages the analyst has opened, for one filter. A filter can change
  // from the address too, when a Needs-you link names one, so the count is
  // kept beside the filter it belongs to and a new filter starts on page 1.
  const [paging, setPaging] = useState<{ filter: AnalyticHitFilter; pages: number }>({
    filter,
    pages: 1,
  });
  const pages = paging.filter === filter ? paging.pages : 1;

  const hits = useAsync(() => readHitPages(filter, pages), [filter, reload, pages], {
    refetchInterval: 60_000,
  });
  const rows = hits.data?.hits ?? [];
  // The total of the filter on screen, from the server. The window can hold
  // more hits than the pages read, and the list said nothing about the rest.
  const total = Math.max(hits.data?.counts?.[filter] ?? 0, rows.length);
  const showMore = () => setPaging({ filter, pages: pages + 1 });
  // Whether the sweeps ran decides what an empty list means. Read on the
  // catalog's own cadence.
  const catalog = useAsync(getHuntCatalog, [], { refetchInterval: 300_000 });

  const wasRead = (hit: AnalyticHit) => hit.read === true || readIds.has(hit.id);

  // The counts come from the same fetch as the rows, and a read does not
  // refetch, so the chips held "Unread 1" over a list with no unread dot until
  // the next poll. The rows hold still on purpose; the numbers do not have to.
  // Each hit the server counted as unread and this session has read comes off
  // the count. A refetch answers with `read` true and the adjustment falls to
  // zero on its own, so the number is never subtracted twice.
  const readHere = rows.filter(
    (h) => h.recorded_in_shadow && h.read === false && readIds.has(h.id),
  ).length;
  const served = hits.data?.counts;
  const counts = served
    ? { ...served, unread: Math.max(0, served.unread - readHere) }
    : undefined;
  // The two windows of the label. A hit this session read comes off the older
  // unread count when its newest sighting is older than the window, by the
  // rule the unread chip follows.
  const servedWindow = hits.data?.window;
  const windowStart = Date.now() - (servedWindow?.days ?? HITS_WINDOW_DAYS) * 86_400_000;
  const readHereOlder = rows.filter(
    (h) =>
      h.recorded_in_shadow &&
      h.read === false &&
      readIds.has(h.id) &&
      h.born_at !== null &&
      Date.parse(h.born_at) < windowStart,
  ).length;
  const hitsWindow = servedWindow
    ? { ...servedWindow, older_unread: Math.max(0, servedWindow.older_unread - readHereOlder) }
    : undefined;
  // W1: with no unread hit the block folds to one line. The analyst opens
  // the hits on request. A filter in the address is a request already, and a
  // list with no hit keeps its empty-state sentence.
  // The fold reads the server's counts. A hit read in this session does not
  // fold the list under the hand that read it, and a list that once held an
  // unread hit stays open.
  const [showQuiet, setShowQuiet] = useState(false);
  const servedUnread = served?.unread;
  useEffect(() => {
    if ((servedUnread ?? 0) > 0) setShowQuiet(true);
  }, [servedUnread]);
  const quiet =
    !showQuiet && !wanted && served !== undefined && served.unread === 0 && served.all > 0;
  const markedRead = (id: number) =>
    setReadIds((prev) => {
      const next = new Set(prev);
      next.add(id);
      return next;
    });

  const setFilter = (next: AnalyticHitFilter) => {
    const search = new URLSearchParams(params);
    if (next === 'all') search.delete('hits');
    else search.set('hits', next);
    setParams(search, { replace: true });
  };

  const changed = () => {
    setReload((n) => n + 1);
    onAnalyticChanged?.();
  };

  return (
    <Panel className="mb-4" id="analytic-hits">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-[15px] py-2.5">
        <span className="flex items-center gap-2 text-[13px] font-semibold">
          {onToggleCollapsed && (
            <CollapseChevron
              collapsed={collapsed}
              onToggle={onToggleCollapsed}
              section="Analytic hits"
              controls={BODY_ID}
            />
          )}
          <span>
            Analytic hits{' '}
            <span
              data-testid="analytic-hits-window"
              className="font-mono text-[11.5px] font-normal text-faint"
              title={
                'The hits that an analytic saw in the last 7 days, and the unread shadow hits ' +
                'that are older. The list holds an unread shadow hit at any age.'
              }
            >
              {counts ? hitsWindowLabel(counts.all, hitsWindow) : `last ${HITS_WINDOW_DAYS} days · —`}
              {/* Folded, the Unread chip is out of sight, and the unread count
                  is the one number that says whether this block holds work. */}
              {collapsed && counts
                ? ` · ${counts.unread} ${hitsWindow ? 'unread in all' : 'unread'}`
                : ''}
            </span>
          </span>
        </span>
        <span className="text-[11.5px] text-dim">{SECTION_NOTE}</span>
      </div>

      {/* What a hit is, before the hits. The definition stays while the section
          is folded: a folded block still says what it holds. */}
      <Definition of="hit" className="px-[15px] pt-2" />

      {collapsed ? (
        <div id={BODY_ID} className="pb-2" />
      ) : quiet ? (
        // W1: no hit waits on the analyst, so the block is one line. Twelve
        // read hits pushed the leads two screens down.
        <div
          id={BODY_ID}
          data-testid="analytic-hits-quiet"
          className="flex flex-wrap items-center gap-2 px-[15px] py-2.5 text-[12.5px] text-dim"
        >
          <span>{`${plural(hitsWindow?.in_window ?? counts?.all ?? 0, 'hit')} in 7 days. None waits on you.`}</span>
          <button
            type="button"
            onClick={() => setShowQuiet(true)}
            className="text-[12px] font-semibold text-accent hover:underline"
          >
            Show hits
          </button>
        </div>
      ) : (
        <div id={BODY_ID}>
      <div className="flex flex-wrap items-center gap-1.5 px-[15px] py-2">
        {FILTERS.map((f) => (
          <button
            key={f.id}
            type="button"
            aria-pressed={filter === f.id}
            onClick={() => setFilter(f.id)}
            title={f.title}
            className={`rounded-chip border px-2 py-px text-[11px] ${
              filter === f.id
                ? 'border-accent text-accent'
                : 'border-border-faint text-dim hover:text-text-2'
            }`}
          >
            {f.label}
            {counts && (
              <span className="ml-1 font-mono tabular-nums text-faint">{counts[f.id]}</span>
            )}
          </button>
        ))}
      </div>

      {/* A failed first read states the failure below. A poll failing after a
          good read kept the cards and the counts with nothing to date them, so
          a dead API read as a fresh list. Two consecutive failures is the house
          threshold: one missed poll is a blip. */}
      {hits.failCount >= 2 && (
        <div className="px-[15px] pb-2">
          <StaleNotice
            since={hits.lastUpdated}
            onRefresh={hits.refetch}
            reason={hits.error ? 'refresh-failed' : 'stale'}
            retrying
          />
        </div>
      )}

      {!hits.data ? (
        <div className="px-[15px] py-2.5 text-[12.5px] text-dim">
          {hits.error ? 'Could not read the analytic hits.' : <LoadingInline>Reading the analytic hits</LoadingInline>}
        </div>
      ) : rows.length === 0 ? (
        // Absence is stated, with the reason it is not an all-clear.
        <div className="px-[15px] py-2.5 text-[12.5px] text-dim">
          {filter === 'all'
            ? emptyHitsText(catalog.data)
            : 'No hit under this filter. Another filter may hold one.'}
        </div>
      ) : (
        <>
          {/* One header for each analytic, and its hits under it. */}
          {groupHits(rows, hits.data.groups, readIds).map((group) => (
            <HitGroupBlock
              key={group.id}
              group={group}
              loadedAt={hits.lastUpdated}
              wasRead={wasRead}
              onRead={markedRead}
              onChange={changed}
              onOpenAnalytic={setOpenAnalytic}
            />
          ))}
          {/* The list held 50 of 148 hits and ended with no word about the
              rest. The line states the share, and the control reads more. */}
          <div className="flex flex-wrap items-center gap-3 border-t border-border-faint px-[15px] py-2.5">
            <span
              data-testid="analytic-hits-shown"
              className="font-mono text-[11.5px] tabular-nums text-dim"
            >
              {rows.length} of {plural(total, 'hit')}
            </span>
            {rows.length < total && (
              <button
                type="button"
                disabled={hits.loading}
                onClick={showMore}
                title={SHOW_MORE_TOOLTIP}
                className="rounded-control border border-border-strong px-3 py-1 text-[11.5px] font-semibold disabled:opacity-50"
              >
                {hits.loading ? 'Reading' : 'Show more'}
              </button>
            )}
          </div>
        </>
      )}
        </div>
      )}

      {/* Mounted only while it is open. `Drawer` registers with the modal
          stack before it renders. */}
      {openAnalytic && (
        <AnalyticDrawer
          analyticId={openAnalytic}
          onClose={() => setOpenAnalytic(null)}
          onChanged={changed}
        />
      )}
    </Panel>
  );
}
