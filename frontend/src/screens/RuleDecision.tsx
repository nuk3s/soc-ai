import { AlertTriangle, ArrowRight, ArrowUpRight, CheckCircle2, CloudOff, Server } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { SeverityTag, VerdictPill } from '../components/Badges';
import { EntityLink } from '../components/EntityLink';
import { Panel, PanelHeader } from '../components/Panel';
import { UtcTime } from '../components/UtcTime';
import { RuleDayBars } from '../components/rule/RuleDayBars';
import { RuleDecisionBar } from '../components/rule/RuleDecisionBar';
import { CONFIDENT_COLOR, WEAK_COLOR } from '../components/rule/RuleRowFacts';
import { ErrorState, LoadingState, NotFoundState } from '../components/States';
import {
  getRuleDecision,
  isNotFound,
  ruleNameOf,
  type RuleDecisionDetail,
  type RuleDecisionGroupName,
  type RuleDecisionMachine,
  type RuleDecisionSample,
} from '../lib/api';
import { machineHref } from '../lib/hostsList';
import {
  RULE_GROUP_ABOUT,
  RULE_GROUP_EMPTY,
  RULE_GROUP_TITLE,
  RULE_PAGE_LABEL,
  groupFactsWords,
  gridReadWords,
  heldWords,
  openAlertsWords,
  reasonLabel,
  ruleSummaryWords,
  samplesOf,
  truePositiveAlarmWords,
  truePositivePairsWords,
} from '../lib/ruleDecision';
import type { Severity } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { useTabTitle } from '../lib/useTabTitle';

// ---------------------------------------------------------------------------
// The decision on one rule (round 3, RC2).
//
// soc-ai gives a false positive verdict and a guard holds the automatic
// acknowledge, so the alert stays open on the grid. The page prepares the
// facts of the rule, and the analyst decides once for all of them. Graphical
// first: one bar chart of the events for each UTC day with the two groups
// stacked, then the machines with their counts, then the two groups. Each
// group states its hold reasons with counts and shows its sample
// investigations. A rule that also holds a true positive states that at the
// top in the danger color. The page states the read time of the grid when
// the grid did not answer. The decision bar sits under the title
// (components/rule/RuleDecisionBar.tsx).
//
// The page reads the rule once a minute.
// ---------------------------------------------------------------------------

const REFETCH_MS = 60_000;

export function RuleDecision() {
  const { ruleKey = '' } = useParams();
  const detail = useAsync<RuleDecisionDetail>(() => getRuleDecision(ruleKey), [ruleKey], {
    refetchInterval: REFETCH_MS,
  });
  const d = detail.data;
  useTabTitle(d?.ruleName || ruleNameOf(ruleKey) || RULE_PAGE_LABEL);

  if (detail.loading && !d) return <LoadingState label="Reading the rule" />;
  if (detail.error && !d) {
    return isNotFound(detail.error) ? (
      <NotFoundState what="rule" id={ruleKey} backTo="/needs-you" backLabel="Back to Needs you" />
    ) : (
      <ErrorState error={detail.error} onRetry={detail.refetch} label="this rule" />
    );
  }
  if (!d) return null;
  const groups = [d.confident, d.weak];

  return (
    <div className="p-5" data-testid="rule-decision-page">
      <RuleHeader d={d} />
      {d.truePositives.length > 0 && <TruePositiveAlarm d={d} />}
      {d.selfAcknowledging?.sentence && (
        <p
          data-testid="rule-self-ack"
          className="mt-2 flex items-start gap-1.5 break-words text-[12.5px] text-text"
        >
          <CheckCircle2 size={13} aria-hidden className="mt-[3px] flex-none text-success" />
          <span className="min-w-0">{d.selfAcknowledging.sentence}</span>
        </p>
      )}
      <GridFacts d={d} />
      {/* The decision is why the analyst opens the page: the bar sits under
          the title, as on the campaign page. */}
      <RuleDecisionBar detail={d} onRefresh={detail.refetch} />
      <RuleDayBars
        days={d.histogram}
        confident={d.confident.count}
        weak={d.weak.count}
        marks={d.truePositives.map((tp) => tp.eventAt?.slice(0, 10) ?? '').filter(Boolean)}
      />
      <Machines machines={d.machines} />
      {(['confident', 'weak'] as const).map((name) => (
        <GroupPanel
          key={name}
          name={name}
          d={d}
          samples={samplesOf(d.samples, name)}
          label={(code) => reasonLabel(code, groups)}
        />
      ))}
      {d.investigationsHref && (
        <Link
          to={d.investigationsHref}
          data-testid="rule-investigations-link"
          className="mt-3 inline-flex items-center gap-1 text-[12.5px] font-semibold text-accent hover:underline"
        >
          Open the investigations of this rule in the list
          <ArrowUpRight size={13} aria-hidden />
        </Link>
      )}
    </div>
  );
}

/** The rule name, the marks of the verdict and the severity, and the count
 *  of each group in one sentence. */
function RuleHeader({ d }: { d: RuleDecisionDetail }) {
  return (
    <header>
      <div className="text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">{RULE_PAGE_LABEL}</div>
      <h1 data-testid="rule-name" className="mt-1 break-words text-[19px] font-semibold">
        {d.ruleName}
      </h1>
      <div className="mt-1.5 flex flex-wrap items-center gap-2">
        <VerdictPill verdict="false_positive" conf={null} />
        <SeverityTag sev={(d.severity ?? 'unknown') as Severity} />
      </div>
      <p data-testid="rule-summary" className="mt-1.5 break-words text-[14px] text-text">
        {ruleSummaryWords(d.confident.count, d.weak.count)}
      </p>
    </header>
  );
}

/** A rule that also holds a true positive verdict: the alarm, in the danger
 *  color, with a link to each investigation. */
function TruePositiveAlarm({ d }: { d: RuleDecisionDetail }) {
  const onPairs = (d.truePositivePairs?.confident ?? 0) + (d.truePositivePairs?.weak ?? 0);
  return (
    <div
      role="alert"
      data-testid="rule-true-positives"
      className="mt-3 rounded-card border border-danger/55 bg-[rgba(240,68,56,.08)] px-3 py-2.5"
    >
      <div className="flex items-start gap-2 text-[13px] font-semibold text-danger">
        <AlertTriangle size={14} aria-hidden className="mt-[3px] flex-none" />
        <span className="min-w-0 break-words">{truePositiveAlarmWords(d.truePositives.length)}</span>
      </div>
      {onPairs > 0 && (
        <p data-testid="rule-true-positive-pairs" className="mt-1 break-words pl-[22px] text-[12.5px] text-text">
          {truePositivePairsWords(onPairs)}
        </p>
      )}
      <ul className="mt-1.5 flex flex-col gap-1 pl-[22px]">
        {d.truePositives.map((tp) => (
          <li key={tp.id} data-testid="rule-true-positive" className="flex flex-wrap items-baseline gap-x-2 text-[12.5px]">
            <span className="min-w-0 break-words text-text">{tp.title}</span>
            <UtcTime className="whitespace-nowrap text-[12px] text-dim" iso={tp.eventAt} seconds={false} />
            <Link
              to={`/investigation/${encodeURIComponent(tp.id)}`}
              className="inline-flex items-center gap-0.5 whitespace-nowrap font-semibold text-accent hover:underline"
            >
              Open the investigation
              <ArrowUpRight size={12} aria-hidden />
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** The state of the grid: the open alerts of the rule, and the read time
 *  when the grid did not answer or soc-ai did not read it yet. */
function GridFacts({ d }: { d: RuleDecisionDetail }) {
  const read = gridReadWords(d.gridAnswered, d.readAt);
  const open = openAlertsWords(d.openAlerts, d.openAlertsDays);
  if (!read && !open) return null;
  return (
    <div className="mt-2 flex flex-col gap-0.5 text-[12.5px]">
      {open && (
        <span data-testid="rule-open-alerts" className="break-words text-text-2">
          {open}
        </span>
      )}
      {read && (
        <span data-testid="rule-grid-read" className="flex items-start gap-1.5 break-words text-warn">
          <CloudOff size={13} aria-hidden className="mt-[3px] flex-none" />
          {read}
        </span>
      )}
    </div>
  );
}

const ROLE_WORD: Record<RuleDecisionMachine['role'], string> = {
  source: 'Source',
  destination: 'Destination',
};

/** The machines with the most investigations, each with its role and a bar of its
 *  count. */
function Machines({ machines }: { machines: readonly RuleDecisionMachine[] }) {
  const peak = Math.max(1, ...machines.map((m) => m.count));
  return (
    <Panel className="mt-3">
      <PanelHeader icon={<Server size={14} />} title="Machines" right={<span className="text-[11.5px] text-faint">The machines with the most investigations</span>} />
      {machines.length === 0 ? (
        <div className="px-[15px] py-3 text-[12.5px] text-dim">No machine is on record.</div>
      ) : (
        <ol data-testid="rule-machines">
          {machines.map((m, i) => {
            const name = m.name || m.address || m.key || 'Unknown machine';
            return (
              <li
                key={`${m.role}|${m.key ?? m.address ?? m.name ?? i}`}
                data-testid="rule-machine"
                data-role={m.role}
                className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-border-faint px-[15px] py-2 first:border-t-0"
              >
                <span className="w-[86px] flex-none text-[11px] font-semibold uppercase tracking-[.05em] text-dim">
                  {ROLE_WORD[m.role] ?? m.role}
                </span>
                <span className="flex min-w-0 flex-[1_1_16rem] flex-wrap items-baseline gap-x-2">
                  {m.key ? (
                    <Link to={machineHref(m.key)} className="break-words font-semibold text-text hover:text-accent hover:underline">
                      {name}
                    </Link>
                  ) : (
                    <span className="break-words font-semibold text-text">{name}</span>
                  )}
                  {m.name && m.address && <span className="font-mono text-[12px] text-text-2">{m.address}</span>}
                  {m.truePositive && (
                    <span
                      data-testid="rule-machine-true-positive"
                      className="inline-flex items-center gap-1 whitespace-nowrap rounded-[5px] border border-danger/55 px-1.5 text-[11px] font-semibold text-danger"
                    >
                      <AlertTriangle size={11} aria-hidden />
                      True positive
                    </span>
                  )}
                </span>
                <span className="flex flex-none items-center gap-2">
                  <svg width={120} height={8} aria-hidden className="flex-none">
                    <rect x={0} y={0} width={120} height={8} rx={2} fill="rgb(var(--border-strong))" />
                    <rect x={0} y={0} width={Math.max(2, (m.count / peak) * 120)} height={8} rx={2} fill={CONFIDENT_COLOR} opacity={0.8} />
                  </svg>
                  <span data-testid="rule-machine-count" className="min-w-[86px] whitespace-nowrap font-mono text-[12px] tabular-nums text-text-2">
                    {m.count.toLocaleString()} {m.count === 1 ? 'investigation' : 'investigations'}
                  </span>
                </span>
              </li>
            );
          })}
        </ol>
      )}
    </Panel>
  );
}

/** One group: what it is, its hold reasons with counts, its facts and its
 *  sample investigations. */
function GroupPanel({
  name,
  d,
  samples,
  label,
}: {
  name: RuleDecisionGroupName;
  d: RuleDecisionDetail;
  samples: readonly RuleDecisionSample[];
  label: (code: string | null) => string | null;
}) {
  const group = d[name];
  const color = name === 'confident' ? CONFIDENT_COLOR : WEAK_COLOR;
  const facts = groupFactsWords(group);
  return (
    <section aria-label={RULE_GROUP_TITLE[name]} data-testid={`rule-group-${name}`} className="mt-3">
      <Panel>
        <div className="flex flex-wrap items-center gap-[9px] border-b border-border px-[15px] py-3">
          <span className="h-[10px] w-[10px] flex-none rounded-[2px]" style={{ background: color }} aria-hidden />
          <h2 className="text-[13px] font-semibold">{RULE_GROUP_TITLE[name]}</h2>
          <span data-testid={`rule-group-${name}-count`} className="font-mono text-[11.5px] tabular-nums text-faint">
            {group.count.toLocaleString()}
          </span>
        </div>
        {group.count === 0 ? (
          <div className="px-[15px] py-3 text-[12.5px] text-dim">{RULE_GROUP_EMPTY[name]}</div>
        ) : (
          <div className="px-[15px] py-3">
            <p className="break-words text-[12.5px] text-text-2">{RULE_GROUP_ABOUT[name]}</p>
            {group.reasons.length > 0 && (
              <ul data-testid={`rule-group-${name}-reasons`} className="mt-2 flex flex-col gap-1">
                {group.reasons.map((r) => (
                  <li key={r.code} data-testid="rule-reason" className="flex flex-wrap items-baseline gap-x-2 text-[12.5px]">
                    <span className="min-w-0 break-words text-text">{r.label || label(r.code)}</span>
                    <span className="font-mono text-[12px] tabular-nums text-text-2">
                      {r.count.toLocaleString()} {r.count === 1 ? 'investigation' : 'investigations'}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            {facts && <p className="mt-2 break-words text-[12px] text-dim">{facts}</p>}
            {samples.length > 0 && (
              <>
                <h3 className="mt-3 text-[11px] font-semibold uppercase tracking-[.06em] text-dim">
                  Sample investigations
                </h3>
                <ol data-testid={`rule-group-${name}-samples`} className="mt-1">
                  {samples.map((s) => (
                    <SampleRow key={s.id} sample={s} reason={label(s.reason)} />
                  ))}
                </ol>
              </>
            )}
          </div>
        )}
      </Panel>
    </section>
  );
}

/** One sample: the event time, the machines, the confidence, the hold
 *  reason, the one sentence of soc-ai and a link. */
function SampleRow({ sample: s, reason }: { sample: RuleDecisionSample; reason: string | null }) {
  return (
    <li
      data-testid="rule-sample"
      className="flex flex-wrap items-start gap-x-4 gap-y-1 border-t border-border-faint py-2 first:border-t-0"
    >
      <span className="flex w-[150px] flex-none flex-col gap-1">
        <VerdictPill verdict="false_positive" conf={s.confidence} />
        <UtcTime
          testId="rule-sample-time"
          className="whitespace-nowrap text-[11.5px] text-faint"
          iso={s.eventAt}
          seconds={false}
        />
      </span>
      <span className="flex min-w-0 flex-[1_1_22rem] flex-col gap-1">
        <span data-testid="rule-sample-machines" className="flex flex-wrap items-center gap-1.5 text-[12px]">
          {s.src ? <EntityLink value={s.src} /> : <span className="text-faint">No source on record</span>}
          <ArrowRight size={12} aria-label="to" className="flex-none text-dim" />
          {s.dst ? <EntityLink value={s.dst} /> : <span className="text-faint">No destination on record</span>}
        </span>
        {s.summary && (
          <span data-testid="rule-sample-summary" className="break-words text-[12.5px] text-text-2">
            {s.summary}
          </span>
        )}
        {reason && (
          <span data-testid="rule-sample-reason" className="break-words text-[12px] text-dim">
            {heldWords(reason)}
          </span>
        )}
      </span>
      <Link
        to={`/investigation/${encodeURIComponent(s.id)}`}
        className="flex flex-none items-center gap-1 whitespace-nowrap text-[12px] font-semibold text-accent hover:underline"
      >
        Open the investigation
        <ArrowUpRight size={13} aria-hidden />
      </Link>
    </li>
  );
}
