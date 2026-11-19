import { useMemo, useState } from 'react';
import type { RuleDecisionDay } from '../../lib/api';
import { TRUE_POSITIVE_DAY_WORDS, dayWords, fillDays } from '../../lib/ruleDecision';
import { useElementWidth } from '../../lib/useElementWidth';
import { HoverTip } from '../campaign/HoverTip';
import { Panel, PanelHeader } from '../Panel';
import { CONFIDENT_COLOR, WEAK_COLOR } from './RuleRowFacts';

/** The mark of a day of a true positive: the danger color. */
const TRUE_POSITIVE_COLOR = 'rgb(var(--danger))';
/** The plot height of the bars, in pixels. */
const PLOT_H = 112;
/** The row of the day labels under the bars. */
const AXIS_H = 22;
/** The left gutter: the count of the highest bar. */
const LEFT = 40;
const RIGHT = 12;
const TOP = 8;
/** The widest bar, in pixels. */
const MAX_BAR = 26;
/** The least space for one day label, in pixels. */
const LABEL_ROOM = 64;
const TIP_W = 260;
/** The side padding of the chart box, in pixels: `px-[15px]`. */
const PAD_X = 15;
/** The top padding of the chart box, in pixels: `pt-3`. */
const PAD_TOP = 12;

interface Hover {
  index: number;
  x: number;
  y: number;
}

/**
 * The investigations of the open false positives of a rule, one bar for each UTC day,
 * the two groups stacked: the ones with checked evidence at the base in the calm tone, the
 * ones with weak evidence on top in the warning tone. A day with no event is
 * a gap on the axis. Each bar states its day and its counts on hover and on
 * keyboard focus. The legend states the total of each group.
 */
export function RuleDayBars({
  days,
  confident,
  weak,
  marks = [],
}: {
  days: readonly RuleDecisionDay[];
  /** The count of each group, for the legend. */
  confident: number;
  weak: number;
  /** The UTC days of the true positives of the rule (F4). The chart marks
   *  each one, and its axis reaches each one. */
  marks?: readonly string[];
}) {
  const [ref, width] = useElementWidth<HTMLDivElement>(960);
  const [hover, setHover] = useState<Hover | null>(null);
  const markKey = marks.join(',');
  const marked = useMemo(() => new Set(markKey ? markKey.split(',') : []), [markKey]);
  const filled = useMemo(
    () => fillDays([...days, ...[...marked].map((day) => ({ day, confident: 0, weak: 0 }))]),
    [days, marked],
  );
  const dayText = (d: RuleDecisionDay) =>
    marked.has(d.day) ? `${dayWords(d)} ${TRUE_POSITIVE_DAY_WORDS}` : dayWords(d);

  if (filled.length === 0) {
    return (
      <Panel className="mt-3">
        <PanelHeader title="Investigations by day" />
        <div data-testid="rule-day-bars-empty" className="px-[15px] py-3 text-[12.5px] text-dim">
          soc-ai holds no event time for the open false positives of this rule.
        </div>
      </Panel>
    );
  }

  // The chart lays its marks out in pixels, so its text stays the size the
  // page sets.
  const svgW = Math.max(LEFT + 120 + RIGHT, width - 2 * PAD_X);
  const plot = svgW - LEFT - RIGHT;
  const slot = plot / filled.length;
  const barW = Math.max(1, Math.min(MAX_BAR, slot * 0.72));
  const peak = Math.max(1, ...filled.map((d) => d.confident + d.weak));
  const height = (v: number) => (v / peak) * PLOT_H;
  const base = TOP + PLOT_H;
  const svgH = base + AXIS_H;
  const labelEvery = Math.max(1, Math.ceil(LABEL_ROOM / slot));
  const last = filled.length - 1;
  const shown = hover ? filled[hover.index] : null;

  return (
    <Panel className="mt-3">
      <PanelHeader
        title="Investigations by day"
        right={<span className="text-[11.5px] text-faint">UTC days. The bars stack the two groups.</span>}
      />
      <div ref={ref} data-testid="rule-day-bars" className="relative px-[15px] pb-2 pt-3">
        <svg
          width={svgW}
          height={svgH}
          role="group"
          aria-label="Investigations of the open false positives for each UTC day"
          onPointerLeave={() => setHover(null)}
        >
          {/* The base line and the count of the highest bar. */}
          <line x1={LEFT} x2={LEFT + plot} y1={base} y2={base} stroke="rgb(var(--border-strong))" />
          <text x={LEFT - 6} y={TOP + 4} textAnchor="end" className="fill-faint font-mono text-[10.5px]">
            {peak.toLocaleString()}
          </text>
          <text x={LEFT - 6} y={base} textAnchor="end" className="fill-faint font-mono text-[10.5px]">
            0
          </text>
          {filled.map((d, i) => {
            const cx = LEFT + slot * i + slot / 2;
            const x = cx - barW / 2;
            const hc = height(d.confident);
            const hw = height(d.weak);
            const words = dayText(d);
            // The last day always has its label. A regular label closer to it
            // than the room of one label gives way: "11-10" sat on "11-13" (D17).
            const label = i === last || (i % labelEvery === 0 && last - i >= labelEvery);
            return (
              <g
                key={d.day}
                data-testid="rule-day"
                data-day={d.day}
                data-confident={d.confident}
                data-weak={d.weak}
              >
                {d.confident > 0 && (
                  <rect
                    data-testid="rule-day-confident"
                    x={x}
                    y={base - hc}
                    width={barW}
                    height={Math.max(1, hc)}
                    fill={CONFIDENT_COLOR}
                    opacity={0.8}
                  />
                )}
                {d.weak > 0 && (
                  <rect
                    data-testid="rule-day-weak"
                    x={x}
                    y={base - hc - Math.max(1, hw)}
                    width={barW}
                    height={Math.max(1, hw)}
                    fill={WEAK_COLOR}
                  />
                )}
                {marked.has(d.day) && (
                  <rect
                    data-testid="rule-day-true-positive"
                    x={cx - Math.max(3, barW / 2)}
                    y={TOP - 6}
                    width={Math.max(6, barW)}
                    height={4}
                    rx={1}
                    fill={TRUE_POSITIVE_COLOR}
                  />
                )}
                {label && (
                  <text
                    data-testid="rule-day-label"
                    x={cx}
                    y={base + 15}
                    textAnchor="middle"
                    className="fill-faint font-mono text-[10.5px]"
                  >
                    {d.day.slice(5)}
                  </text>
                )}
                {/* The hit area: the whole slot, for the pointer and the keyboard. */}
                <rect
                  x={LEFT + slot * i}
                  y={TOP}
                  width={slot}
                  height={PLOT_H}
                  fill="transparent"
                  tabIndex={d.confident + d.weak > 0 ? 0 : -1}
                  role="img"
                  aria-label={words}
                  className="outline-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-accent"
                  onPointerMove={() => setHover({ index: i, x: cx, y: base - hc - hw })}
                  onFocus={() => setHover({ index: i, x: cx, y: base - hc - hw })}
                  onBlur={() => setHover(null)}
                />
              </g>
            );
          })}
        </svg>
        {shown && hover && (
          <HoverTip
            container={ref.current}
            x={PAD_X + hover.x - TIP_W / 2}
            y={PAD_TOP + hover.y}
            width={TIP_W}
            gap={8}
            rise={12}
            testId="rule-day-tip"
          >
            <span className="break-words text-text-2">{dayText(shown)}</span>
          </HoverTip>
        )}
        <div data-testid="rule-day-legend" className="mt-1.5 flex flex-wrap gap-4 font-mono text-[11px] text-dim">
          <span className="flex items-center gap-1.5">
            <span className="h-[9px] w-[9px] rounded-[2px]" style={{ background: CONFIDENT_COLOR, opacity: 0.8 }} />
            Checked evidence {confident.toLocaleString()}
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-[9px] w-[9px] rounded-[2px]" style={{ background: WEAK_COLOR }} />
            Weak evidence {weak.toLocaleString()}
          </span>
          {marked.size > 0 && (
            <span data-testid="rule-day-legend-true-positive" className="flex items-center gap-1.5">
              <span className="h-[4px] w-[9px] rounded-[1px]" style={{ background: TRUE_POSITIVE_COLOR }} />
              True positive
            </span>
          )}
        </div>
      </div>
    </Panel>
  );
}
