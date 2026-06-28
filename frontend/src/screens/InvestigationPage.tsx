import { ChevronLeft, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';
import { deleteInvestigation, getInvestigation } from '../lib/api';
import { useAsync } from '../lib/useAsync';
import { ErrorState, LoadingState } from '../components/States';
import { Investigation } from './Investigation';

/** Investigation permalink: /investigation/:id — wide workstation layout. */
export function InvestigationPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from;
  const backTo = from === '/investigations' ? '/investigations' : '/alerts';
  const backLabel = from === '/investigations' ? 'Investigations' : 'Alerts';
  const [tick, setTick] = useState(0);
  const { data: inv, loading, error } = useAsync(() => getInvestigation(id), [id, tick]);
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

  // Poll a running investigation until it lands a verdict.
  useEffect(() => {
    if (inv?.status !== 'investigating') return;
    const t = setTimeout(() => setTick((x) => x + 1), 2500);
    return () => clearTimeout(t);
  }, [inv, tick]);

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
      {error && (
        <div className="mx-auto max-w-workstation">
          <ErrorState error={error} />
        </div>
      )}
      {inv && (
        <Investigation inv={inv} layout="page" onReHunt={(newId) => navigate(`/investigation/${newId}`)} onVerdictApplied={() => setTick((x) => x + 1)} />
      )}
    </div>
  );
}
