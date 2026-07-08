import { ArrowRight, BookOpen } from 'lucide-react';
import { Link } from 'react-router-dom';
import { getRunbooks } from '../lib/api';
import { CollapseChevron } from '../components/Panel';
import { useAsync } from '../lib/useAsync';

/**
 * Compact Config-page summary for operator runbooks.
 *
 * Authoring moved to its own top-level page (/runbooks — see Runbooks.tsx):
 * the full editor buried at the bottom of Config was undiscoverable, and a
 * knowledge corpus the agent cites deserves nav real estate. This stub keeps
 * the Config section (and its #runbooks deep-link / left-nav entry) alive as
 * a signpost: the count plus a manage link, next to the Retrieval (RAG)
 * settings that govern how runbooks are searched.
 */
export function RunbooksPanel({
  collapsed = false,
  onToggleCollapse,
}: {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
} = {}) {
  const { data } = useAsync(getRunbooks, []);
  const count = data?.length;

  return (
    <div id="runbooks" className="mb-[22px] scroll-mt-6">
      <div className="mb-1 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="text-[15px] font-semibold">Runbooks</div>
          {onToggleCollapse && (
            <CollapseChevron collapsed={collapsed} onToggle={onToggleCollapse} label="Toggle Runbooks" />
          )}
        </div>
      </div>
      {!collapsed && (
        <div className="flex items-center gap-3.5 rounded-card border border-border bg-surface-1 px-[15px] py-[13px]">
          <span className="flex-none text-faint">
            <BookOpen size={16} />
          </span>
          <div className="min-w-0 flex-1 text-[12.5px] leading-[1.5] text-dim">
            Your team's own triage guidance, searched and cited by the investigation agent (the{' '}
            <code className="text-[11.5px] text-text">lookup_runbook</code> tool). Author, import
            .md files, or load the starter pack on the Runbooks page.
          </div>
          <Link
            to="/runbooks"
            className="inline-flex flex-none items-center gap-1.5 rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent"
          >
            {count === undefined ? 'Manage runbooks' : `${count} runbook${count === 1 ? '' : 's'} · manage`}
            <ArrowRight size={12} />
          </Link>
        </div>
      )}
    </div>
  );
}
