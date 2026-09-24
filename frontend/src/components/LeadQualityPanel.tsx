import { GitBranch } from 'lucide-react';

import { getLeadQuality, type LeadQualityWeek } from '../lib/api';
import {
  LEAD_QUALITY,
  QUALITY_DISMISSED,
  QUALITY_FORMED,
  QUALITY_HUNTED,
  QUALITY_PROMOTED,
  QUALITY_THREAT,
  QUALITY_TYPES,
  QUALITY_TYPES_DISMISSED,
  QUALITY_TYPES_FORMED,
  QUALITY_TYPES_THREAT,
  QUALITY_WEEK,
} from '../lib/tooltips';
import { kindLabel } from '../lib/kinds';
import { useAsync } from '../lib/useAsync';
import { REASON_LABEL } from './LeadsStrip';

/** The types that formed a lead, in the analyst's words. The API joins the
 *  stored names with a plus sign. */
function typesLabel(types: string): string {
  return types
    .split('+')
    .map((t) => kindLabel(t.trim()))
    .join(' + ');
}
import { Panel, PanelHeader } from './Panel';
import { Freshness, LoadingState } from './States';

// ---------------------------------------------------------------------------
// Lead quality — what the lead rule produced.
//
// The rule stays where it is. This block is the instrument on it: per week,
// how many leads formed, how many were hunted, how many the hunt found a
// threat on, how many an analyst promoted, and how many an analyst dismissed
// under each reason. Then the same counts per set of observation types, which
// is the question "which pair of signals is worth forming a lead on".
//
// The two sentences come from the server. The rule is the code's own words for
// its constants, so the block cannot drift from the thresholds it measures.
// The note is the noise floor rule: a threshold moves on a week of data, never
// on a day.
//
// A failed read states the failure. "No lead formed" over a dead endpoint is
// the false all-clear this whole surface exists to prevent.
// ---------------------------------------------------------------------------

/** The window the block reads. Four weeks is the shortest run that can show a
 *  trend under the noise floor rule, and the rule says a day never can. */
const WEEKS = 4;

/** Every dismissal reason any week in the payload carries, in the key order
 *  the server writes them under. A column for a reason nobody used is noise,
 *  and a reason with no column loses the dismissal it counted. */
export function dismissalColumns(weeks: readonly LeadQualityWeek[]): string[] {
  const seen = new Set<string>();
  for (const w of weeks) for (const reason of Object.keys(w.dismissed)) seen.add(reason);
  return [...seen].sort();
}

const HEAD_CLASS = 'px-2 py-1.5 text-[10.5px] font-semibold uppercase tracking-[.05em] text-faint';
const CELL_CLASS = 'px-2 py-1.5 font-mono text-[11.5px] tabular-nums text-dim';

export function LeadQualityPanel() {
  const quality = useAsync(() => getLeadQuality(WEEKS), [], { refetchInterval: 300_000 });
  const data = quality.data;
  const reasons = dismissalColumns(data?.weeks ?? []);
  const empty = data !== null && data.weeks.length === 0 && data.by_types.length === 0;

  return (
    <Panel className="mt-4">
      <PanelHeader
        icon={<GitBranch size={16} />}
        title={<span title={LEAD_QUALITY}>Lead quality</span>}
        right={<Freshness at={quality.lastUpdated} />}
      />
      {!data ? (
        quality.error ? (
          <div className="px-[15px] py-3 text-[13px] text-dim">Could not read the lead quality.</div>
        ) : (
          <LoadingState label="Reading the lead quality…" />
        )
      ) : (
        <>
          {/* The rule the numbers measure, in the words of the code that holds
              the constants. */}
          <div
            data-testid="lead-quality-rule"
            className="border-b border-border-faint px-[15px] py-2 text-[12.5px] text-text-2"
          >
            {data.rule}
          </div>
          <div
            data-testid="lead-quality-note"
            className="border-b border-border-faint px-[15px] py-1.5 text-[11.5px] text-dim"
          >
            {data.note}
          </div>
          {empty ? (
            <div className="px-[15px] py-3 text-[12.5px] text-dim">
              No lead formed in the window. The rule has produced nothing to read.
            </div>
          ) : (
            <>
              {data.weeks.length > 0 && (
                <table
                  data-testid="lead-quality-weeks"
                  className="w-full table-auto text-left"
                >
                  <thead>
                    <tr>
                      <th className={`${HEAD_CLASS} pl-[15px]`} title={QUALITY_WEEK}>
                        Week
                      </th>
                      <th className={HEAD_CLASS} title={QUALITY_FORMED}>
                        Formed
                      </th>
                      <th className={HEAD_CLASS} title={QUALITY_HUNTED}>
                        Hunted
                      </th>
                      <th className={HEAD_CLASS} title={QUALITY_THREAT}>
                        Threat
                      </th>
                      <th className={HEAD_CLASS} title={QUALITY_PROMOTED}>
                        Promoted
                      </th>
                      {/* One column per reason the data carries. The header is
                          the analyst's word for the reason, the same word the
                          dismiss form offered. */}
                      {reasons.map((r) => (
                        <th key={r} className={HEAD_CLASS} title={QUALITY_DISMISSED}>
                          {REASON_LABEL[r] ?? r}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {data.weeks.map((w) => (
                      <tr
                        key={w.week}
                        data-testid={`quality-week-${w.week}`}
                        className="border-t border-border-faint"
                      >
                        <td className={`${CELL_CLASS} pl-[15px] text-text-2`}>{w.week}</td>
                        <td className={CELL_CLASS}>{w.formed}</td>
                        <td className={CELL_CLASS}>{w.hunted}</td>
                        <td className={CELL_CLASS}>{w.threat}</td>
                        <td className={CELL_CLASS}>{w.promoted}</td>
                        {reasons.map((r) => (
                          <td key={r} className={CELL_CLASS}>
                            {w.dismissed[r] ?? 0}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              {data.by_types.length > 0 && (
                <table
                  data-testid="lead-quality-types"
                  className="w-full table-auto border-t border-border text-left"
                >
                  <thead>
                    <tr>
                      <th className={`${HEAD_CLASS} pl-[15px]`} title={QUALITY_TYPES}>
                        Types
                      </th>
                      <th className={HEAD_CLASS} title={QUALITY_TYPES_FORMED}>
                        Formed
                      </th>
                      <th className={HEAD_CLASS} title={QUALITY_TYPES_DISMISSED}>
                        Dismissed
                      </th>
                      <th className={HEAD_CLASS} title={QUALITY_TYPES_THREAT}>
                        Threat
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.by_types.map((t, i) => (
                      <tr
                        key={t.types}
                        data-testid={`quality-types-${i}`}
                        className="border-t border-border-faint"
                      >
                        <td className={`${CELL_CLASS} pl-[15px] text-text-2`}>{typesLabel(t.types)}</td>
                        <td className={CELL_CLASS}>{t.formed}</td>
                        <td className={CELL_CLASS}>{t.dismissed}</td>
                        <td className={CELL_CLASS}>{t.threat}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}
        </>
      )}
    </Panel>
  );
}
