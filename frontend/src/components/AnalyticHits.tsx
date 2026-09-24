import { useState, type ReactNode } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';

import {
  getAnalyticHits,
  markShadowHitRead,
  setAnalyticStatus,
  startHuntConsole,
  type AnalyticHit,
  type AnalyticHitFilter,
} from '../lib/api';
import { entityPath as pathOfEntity } from '../lib/entityPath';
import { plural } from '../lib/plural';
import { absTime, ago } from '../lib/timeRange';
import {
  CHIP_LIVE,
  CHIP_LOCAL,
  CHIP_NO_LEAD,
  CHIP_RECORDED_IN_SHADOW,
  CHIP_SHADOW,
  CHIP_SHIPPED,
  HIT_FILTER_ALL,
  HIT_FILTER_LIVE,
  HIT_FILTER_SHADOW,
  HIT_FILTER_UNREAD,
  UNREAD_DOT,
  chipRead,
} from '../lib/tooltips';
import { useAsync } from '../lib/useAsync';
import { AnalyticDrawer } from './AnalyticDrawer';
import { Definition } from './Definition';
import { DocumentChip } from './DocumentDrawer';
import { CollapseChevron, Panel } from './Panel';
import { StaleNotice } from './States';

// ---------------------------------------------------------------------------
// Analytic hits — every hit an analytic wrote in the last 7 days, live and
// shadow, in one list.
//
// A hit is an observation an analytic wrote. The old band held the shadow hits
// alone, so the real signal had no surface and a shadow hit read as the only
// thing the analytics produce. Live hits come first here, newest first. Shadow
// hits follow, unread first.
//
// A card names two things. The analytic is the logic. The hit is the instance
// the analytic wrote. The owner's rule: the real hit is never lighter than the
// provisional one. A live hit carries a solid accent border and a bold title. A
// shadow hit carries a dashed amber border and a normal title. A read shadow
// hit is dimmer still.
//
// A hit whose receipts are incomplete reads "could not run" and names the
// missing part. It is never shown as a hit and it is never hidden.
// ---------------------------------------------------------------------------

const AMBER = '#d29922';

/** The block the chevron folds. The anchor `analytic-hits` stays on the panel,
 *  so a link still reaches the header of a folded section. */
const BODY_ID = 'analytic-hits-body';

const SECTION_NOTE =
  'What the analytics found. Live hits come first. Then shadow hits, unread first.';

const TITLE_TOOLTIP = 'Open the analytic: its definition, its ledger and its versions.';

const FILTERS: { id: AnalyticHitFilter; label: string; title: string }[] = [
  { id: 'all', label: 'All', title: HIT_FILTER_ALL },
  { id: 'unread', label: 'Unread', title: HIT_FILTER_UNREAD },
  { id: 'live', label: 'Live', title: HIT_FILTER_LIVE },
  { id: 'shadow', label: 'Shadow', title: HIT_FILTER_SHADOW },
];

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
  const r = hit.receipts!;
  const ids = r.matched_ids ?? [];
  const dry = r.dry_run;
  const entities = dry?.entities ?? [];
  const overlap = r.overlap ?? [];
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
      {r.baseline && (
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
  onOpenAnalytic,
}: {
  hit: AnalyticHit;
  /** True once the analyst has read it, from the server or from this session.
   *  The block holds the session part, so the list does not reorder under the
   *  hand that is working it. */
  read: boolean;
  onRead: (id: number) => void;
  onChange: () => void;
  onOpenAnalytic: (id: string) => void;
}) {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [approving, setApproving] = useState(false);
  const [rejecting, setRejecting] = useState(false);
  const [why, setWhy] = useState('');
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);

  // Two facts, and the card read one of them as both. The status is the
  // analytic today: it carries the chip and the two decisions. The flag says
  // where the hit was recorded: it picks the half, the border, the weight and
  // the read state, and it holds until the sweep writes the row again.
  const liveAnalytic = hit.analytic_status === 'live';
  const shadowAnalytic = hit.analytic_status === 'shadow';
  const recordedLive = !hit.recorded_in_shadow;
  // `complete` false is the packet's own verdict on itself. A shadow hit must
  // prove itself, so the state word and the flag must agree before the card
  // claims a hit. A live hit has already been approved, and a packet without
  // receipts is not a reason to call its hit unproven.
  const provable = hit.state === 'hit' && (recordedLive || (hit.receipts?.complete ?? false));
  const unread = !recordedLive && !read;

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

  // The decision is what reads the hit. The server names the statuses one
  // status can move to, and that sentence is the answer to a refusal.
  const decide = async (to: 'live' | 'retired') => {
    setBusy(true);
    setFailed(null);
    try {
      await setAnalyticStatus(hit.analytic_id, to, why);
      setApproving(false);
      setRejecting(false);
      setWhy('');
      await markRead();
      onChange();
    } catch (e) {
      setFailed(
        e instanceof Error && e.message ? e.message : 'The status did not change. Try again.',
      );
    } finally {
      setBusy(false);
    }
  };

  // The stored summary first: the analytic wrote it about this instance. When
  // it repeats the two lines above it, the dry run is the fact that does not.
  const summary = summaryBody(hit) ?? dryRunLine(hit);
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
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
            Analytic:
          </span>
          {unread && (
            <span
              className="h-[7px] w-[7px] flex-none rounded-full"
              style={{ background: AMBER, boxShadow: '0 0 0 3px rgba(210,153,34,.25)' }}
              title={UNREAD_DOT}
            />
          )}
          <button
            type="button"
            data-testid="analytic-hit-title"
            className={`text-left text-[13px] hover:underline ${
              recordedLive ? 'font-bold' : 'font-medium'
            }`}
            title={TITLE_TOOLTIP}
            onClick={() => onOpenAnalytic(hit.analytic_id)}
          >
            {hit.analytic_title}
          </button>
          <Chip
            label={hit.analytic_status}
            title={liveAnalytic ? CHIP_LIVE : CHIP_SHADOW}
            tone={liveAnalytic ? 'live' : 'shadow'}
          />
          {/* The hit lists under Shadow and its analytic reads live. The chip
              states why, so the two words do not read as a contradiction. */}
          {!recordedLive && liveAnalytic && (
            <Chip label="recorded in shadow" title={CHIP_RECORDED_IN_SHADOW} tone="faint" />
          )}
          <Chip
            label={hit.tier === 'shipped' ? 'shipped' : 'local'}
            title={hit.tier === 'shipped' ? CHIP_SHIPPED : CHIP_LOCAL}
          />
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

        <div className="mt-1.5 flex flex-wrap items-center gap-2">
          <span className="text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
            Hit:
          </span>
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
            <Chip label="no lead" title={CHIP_NO_LEAD} tone="faint" />
          )}
        </div>

        {summary && (
          <div data-testid="analytic-hit-summary" className="mt-1.5 text-[12.5px] text-text-2">
            {summary}
          </div>
        )}
        {!provable && (
          <div className="mt-1.5 text-[11.5px] leading-[1.6] text-dim">
            {`The evidence is incomplete. Missing: ${missingText(hit)}. This analytic did not ` +
              'prove its hit. This is not an all-clear.'}
          </div>
        )}

        <div className="mt-2 flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={toggleEvidence}
            className="rounded-control border border-border-strong px-3 py-1 text-[11.5px] font-semibold"
          >
            {open ? 'Hide evidence' : 'Show evidence'}
          </button>
          <span className="text-[11px] text-dim">
            {plural(hit.document_count, 'document id')}
          </span>
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
          <button
            type="button"
            disabled={busy}
            onClick={hunt}
            className="rounded-control bg-accent px-3 py-1 text-[11.5px] font-semibold text-white disabled:opacity-50"
          >
            Hunt this entity
          </button>
        )}
        {/* The decisions are about the analytic, so they follow its status.
            The card offered the approval on an analytic an analyst had approved
            already, because it read the flag on the row as the status. */}
        {shadowAnalytic && provable && (
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              setApproving(true);
              setRejecting(false);
            }}
            className="rounded-control border px-3 py-1 text-[11.5px] font-semibold disabled:opacity-50"
            style={{ color: AMBER, borderColor: 'rgba(210,153,34,.5)' }}
          >
            Approve analytic
          </button>
        )}
        {shadowAnalytic && (
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              setRejecting(true);
              setApproving(false);
            }}
            className="rounded-control px-3 py-1 text-[11.5px] text-dim disabled:opacity-50"
          >
            Reject analytic
          </button>
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

      {open && (hit.receipts ? <Evidence hit={hit} /> : <div className="col-span-2 text-[11.5px] text-dim">No evidence.</div>)}
      {(approving || rejecting) && (
        <div className="col-span-2 flex flex-wrap items-center gap-2 text-[12px]">
          {/* "Reject" named no outcome. The analytic is retired, it stops
              running, and the reason is stored on the transition. */}
          <span data-testid="analytic-decision-note" className="basis-full text-[11.5px] text-dim">
            {approving
              ? 'The analytic goes live with this reason. It raises what it finds.'
              : 'The analytic is retired with this reason. It stops running.'}
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
            onClick={() => decide(approving ? 'live' : 'retired')}
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
    </li>
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

  const hits = useAsync(() => getAnalyticHits({ days: 7, filter, limit: 50 }), [filter, reload], {
    refetchInterval: 60_000,
  });
  const rows = hits.data?.hits ?? [];

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
            <span className="font-mono text-[11.5px] font-normal text-faint">
              last 7 days · {counts ? counts.all : '—'}
              {/* Folded, the Unread chip is out of sight, and the unread count
                  is the one number that says whether this block holds work. */}
              {collapsed && counts ? ` · ${counts.unread} unread` : ''}
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
          {hits.error ? 'Could not read the analytic hits.' : 'Reading the analytic hits…'}
        </div>
      ) : rows.length === 0 ? (
        // Absence is stated, with the reason it is not an all-clear.
        <div className="px-[15px] py-2.5 text-[12.5px] text-dim">
          {filter === 'all'
            ? 'No analytic hit in the last 7 days. No analytic matched a document the sweeps read.'
            : 'No hit under this filter. Another filter may hold one.'}
        </div>
      ) : (
        <ul>
          {rows.map((hit) => (
            <HitCard
              key={hit.id}
              hit={hit}
              read={wasRead(hit)}
              onRead={markedRead}
              onChange={changed}
              onOpenAnalytic={setOpenAnalytic}
            />
          ))}
        </ul>
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
