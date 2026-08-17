import { ChevronLeft, Trash2 } from 'lucide-react';
import { useRef, useState } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';
import { deleteInvestigation, getInvestigation, isNotFound } from '../lib/api';
import { useAsync } from '../lib/useAsync';
import { ErrorState, LoadingState, NotFoundState, StaleNotice } from '../components/States';
import { Investigation } from './Investigation';

/** Investigation permalink: /investigation/:id — wide workstation layout. */
export function InvestigationPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from;
  const backTo = from === '/investigations' ? '/investigations' : '/alerts';
  const backLabel = from === '/investigations' ? 'Investigations' : 'Alerts';
  const [reloadKey, setReloadKey] = useState(0);
  // useAsync captures pauseWhen at setup and can't see `inv` there, so track the
  // status in a ref and let pauseWhen consult it. Driving the live refresh
  // through refetchInterval (background polls) instead of a foreground `tick`
  // dep means a single failed poll keeps the last-good report on screen and
  // never wedges the view — a foreground fetch nulls data on error, which used
  // to discard the report and stop the poll loop permanently.
  const statusRef = useRef<string | undefined>(undefined);
  const { data: inv, loading, error, lastUpdated } = useAsync(() => getInvestigation(id), [id, reloadKey], {
    refetchInterval: 2500,
    pauseWhen: () => {
      const s = statusRef.current;
      return s !== undefined && s !== 'investigating';
    },
  });
  statusRef.current = inv?.status;
  const [confirmDel, setConfirmDel] = useState(false);
  const [delErr, setDelErr] = useState('');

  const doDelete = async () => {
    setDelErr('');
    try {
      await deleteInvestigation(inv?.id ?? id);
      navigate(backTo);
    } catch (e) {
      setDelErr(e instanceof Error ? e.message : 'Delete failed (admin only)');
      setConfirmDel(false);
    }
  };

  // Guard: no id means this route was reached without a valid investigation id.
  if (!id) {
    return (
      <div className="px-[22px] pb-[60px] pt-[18px]">
        <div className="mx-auto max-w-workstation">
          <ErrorState error={new Error('No investigation id provided.')} />
        </div>
      </div>
    );
  }

  return (
    <div className="px-[22px] pb-[60px] pt-[18px]">
      <div className="mx-auto mb-4 flex max-w-workstation items-center gap-3">
        <Link to={backTo} className="flex items-center gap-1.5 text-[12.5px] text-dim hover:text-text">
          <ChevronLeft size={13} /> {backLabel}
        </Link>
        <span className="text-ghost">/</span>
        <div className="text-[14px] font-semibold">Investigation</div>
        <span className="rounded-badge border border-border-2 bg-surface-1 px-2 py-0.5 font-mono text-[11.5px] text-dim">
          {inv?.id ?? id}
        </span>
        <div className="flex-1" />
        {inv &&
          (inv.status === 'investigating' ? (
            <div className="flex items-center gap-1.5 rounded-badge border border-[rgba(75,139,245,.3)] bg-[rgba(75,139,245,.07)] px-[9px] py-[3px] font-mono text-[11.5px] text-accent">
              <span className="h-1.5 w-1.5 animate-pulseDot rounded-full bg-accent" />
              investigating · {inv.elapsedLabel}
            </div>
          ) : inv.status === 'error' ? (
            <div className="flex items-center gap-1.5 rounded-badge border border-[rgba(240,68,56,.3)] bg-[rgba(240,68,56,.07)] px-[9px] py-[3px] font-mono text-[11.5px] text-danger">
              <span className="h-1.5 w-1.5 rounded-full bg-danger" />
              failed · {inv.elapsedLabel}
            </div>
          ) : inv.status === 'cancelled' || inv.status === 'interrupted' ? (
            // Don't render a cancelled/interrupted run as green "complete" — it
            // contradicted the failure banner below. Amber, with the real status.
            <div className="flex items-center gap-1.5 rounded-badge border border-[rgba(210,153,34,.3)] bg-[rgba(210,153,34,.07)] px-[9px] py-[3px] font-mono text-[11.5px] text-[#d29922]">
              <span className="h-1.5 w-1.5 rounded-full bg-[#d29922]" />
              {inv.status} · {inv.elapsedLabel}
            </div>
          ) : (
            <div className="flex items-center gap-1.5 rounded-badge border border-[rgba(63,185,80,.3)] bg-[rgba(63,185,80,.07)] px-[9px] py-[3px] font-mono text-[11.5px] text-success">
              <span className="h-1.5 w-1.5 rounded-full bg-success" />
              complete · {inv.elapsedLabel}
            </div>
          ))}
        {inv && inv.status !== 'investigating' && (
          confirmDel ? (
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => { void doDelete(); }}
                className="flex items-center gap-1.5 rounded-badge border border-danger px-2.5 py-[3px] text-[11.5px] font-semibold text-danger hover:bg-[rgba(240,68,56,.12)]"
              >
                <Trash2 size={12} /> Confirm delete
              </button>
              <button
                onClick={() => setConfirmDel(false)}
                className="rounded-badge border border-border-strong px-2.5 py-[3px] text-[11.5px] font-semibold text-dim hover:text-text"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              onClick={() => setConfirmDel(true)}
              title="Delete this investigation (admin)"
              className="flex items-center gap-1.5 rounded-badge border border-border-strong px-2.5 py-[3px] text-[11.5px] font-semibold text-dim hover:border-danger hover:text-danger"
            >
              <Trash2 size={12} /> Delete
            </button>
          )
        )}
      </div>
      {delErr && (
        <div className="mx-auto mb-3 max-w-workstation text-[12px] text-danger">{delErr}</div>
      )}

      {/* Only on the first load — never on a poll refresh (it would remount the
          page subtree, causing the flicker + scanline reset). */}
      {loading && !inv && (
        <div className="mx-auto max-w-workstation">
          <LoadingState label="Loading investigation…" />
        </div>
      )}
      {/* A 404 is an answer, not an incident: "this run doesn't exist" and "the
          grid is down" read identically when both render the alarm card.

          Gated on `!inv`, matching HostDetail and HuntDetail: this block and
          the investigation below are siblings, not a chain, so without it a
          failure arriving after the page was populated stacked an error card ON
          TOP of the report it was reporting the loss of. These states answer
          "the first load failed", and only that. */}
      {error && !inv && (
        <div className="mx-auto max-w-workstation">
          {isNotFound(error) ? (
            <NotFoundState
              what="investigation"
              id={id}
              backTo={backTo}
              backLabel={`Back to ${backLabel}`}
            />
          ) : (
            // A genuine outage is the one failure the analyst can act on: wait
            // a moment and ask again. Without this the card's only affordance
            // was a Details disclosure, leaving a browser reload as the way
            // forward — on the one detail screen of the three that never wired
            // the Retry the card already had. (NotFoundState above still has
            // none, deliberately: retrying a 404 fails again.)
            <ErrorState
              error={error}
              onRetry={() => setReloadKey((x) => x + 1)}
              label="this investigation"
            />
          )}
        </div>
      )}
      {/* The other half of the `!inv` gate above. Keeping the report on screen
          through a failure is right; saying NOTHING about the failure is not —
          the analyst goes on reading a report that may have moved on (a verdict
          applied in another tab, a run that finished) with no sign the refresh
          never landed. Non-destructive by construction: a strip above the
          report, and the report itself untouched.

          A run still investigating is still polled (pauseWhen only stops on a
          terminal status), so there the failed click is not the last word and
          the copy keeps the retry promise; on a finished run the poll loop is
          parked and the Refresh button really is the whole way forward. */}
      {inv && error && (
        <div className="mx-auto mb-3 max-w-workstation">
          <StaleNotice
            since={lastUpdated}
            onRefresh={() => setReloadKey((x) => x + 1)}
            reason="refresh-failed"
            retrying={inv.status === 'investigating'}
          />
        </div>
      )}
      {inv && (
        <Investigation inv={inv} layout="page" onReHunt={(newId) => navigate(`/investigation/${newId}`)} onVerdictApplied={() => setReloadKey((x) => x + 1)} />
      )}
    </div>
  );
}
