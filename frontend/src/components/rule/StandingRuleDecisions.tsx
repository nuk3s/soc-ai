import { useEffect, useState } from 'react';
import { ArrowUpRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import { getRuleDecisions, onNeedsYouChanged, type RuleDecisionList } from '../../lib/api';
import { STANDING_FOLD_TITLE, standingEntryRule, standingEntryWords } from '../../lib/ruleDecision';
import { useAsync } from '../../lib/useAsync';
import { Fold } from '../campaign/Fold';

const REFETCH_MS = 60_000;

/**
 * The standing rule decisions in force (round 3, RC5): one fold under the
 * list of Needs you. Each row names the rule with a link to its page, the end
 * date and the false positives that soc-ai acknowledged under it. The fold is
 * closed by default. It is absent when no standing decision is in force and
 * when the read fails: a standing decision waits on no one.
 */
export function StandingRuleDecisions() {
  const list = useAsync<RuleDecisionList>(() => getRuleDecisions(), [], { refetchInterval: REFETCH_MS });
  const { refetch } = list;
  useEffect(() => onNeedsYouChanged(() => refetch()), [refetch]);
  const [open, setOpen] = useState(false);
  const rows = (list.data?.standing ?? []).flatMap((entry) => {
    const rule = standingEntryRule(entry);
    return rule ? [{ entry, rule }] : [];
  });
  if (rows.length === 0) return null;
  return (
    <div className="mt-3">
      <Fold
        title={STANDING_FOLD_TITLE}
        count={rows.length}
        open={open}
        onToggle={() => setOpen((o) => !o)}
        testId="needs-you-standing"
      >
        <ol>
          {rows.map(({ entry, rule }) => (
            <li
              key={String(entry.id)}
              data-testid="needs-you-standing-row"
              className="flex flex-wrap items-baseline gap-x-4 gap-y-1 border-t border-border-faint px-[15px] py-2.5 first:border-t-0"
            >
              <span className="flex min-w-0 flex-[1_1_22rem] flex-col gap-0.5">
                <span className="break-words text-[13px] font-semibold text-text">{rule.name}</span>
                <span data-testid="needs-you-standing-facts" className="break-words text-[12px] text-text-2">
                  {standingEntryWords(entry)}
                </span>
              </span>
              <Link
                to={rule.href}
                className="flex flex-none items-center gap-1 whitespace-nowrap text-[12px] font-semibold text-accent hover:underline"
              >
                Open the rule
                <ArrowUpRight size={13} aria-hidden />
              </Link>
            </li>
          ))}
        </ol>
      </Fold>
    </div>
  );
}
