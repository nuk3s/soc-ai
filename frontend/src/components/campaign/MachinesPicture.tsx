import { useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import type { CampaignRole } from '../../lib/api';

/** The width of the column of lines between the actors and the targets. */
const LINK_COLUMN = 72;
const INSIDE_INK = 'rgb(var(--text-2))';
const LOUD_INK = 'rgb(var(--danger))';

/** A machine of the picture. */
export interface PictureParty {
  machineKey: string;
  role: CampaignRole;
}

/** A line of the picture: one attack between two machines. */
export interface PictureLine {
  source: string;
  target: string;
}

/**
 * The machines of a campaign as the attack graph draws them, small: the
 * actors on the left, the targets in the middle, the targets that only a
 * target acted on to the right, and one line for each attack between two
 * columns. The page reads the row centers after the layout, so a name that
 * wraps keeps its line.
 *
 * The dialog "Record authorized activity" draws each machine as a check box
 * and a line with an unlisted end dashed in the danger tone. The dialog "Open
 * one case" draws each machine as the case names it, and each line solid.
 * `testId` names the parts: `{testId}-picture`, `-actors`, `-targets`,
 * `-further` and `-line`.
 */
export function MachinesPicture<P extends PictureParty, L extends PictureLine>({
  testId,
  actors,
  targets,
  further,
  lines,
  row,
  inside = () => true,
  color,
  legend,
}: {
  testId: string;
  actors: P[];
  targets: P[];
  further: P[];
  lines: readonly L[];
  /** One machine. The picture keeps its center for the lines. */
  row: (p: P) => ReactNode;
  /** True for a solid line. A line that is not inside is dashed in the danger tone. */
  inside?: (line: L) => boolean;
  /** The ink of a solid line. The muted text tone by default. */
  color?: (line: L) => string;
  legend?: ReactNode;
}) {
  const boxRef = useRef<HTMLDivElement>(null);
  const rowRefs = useRef(new Map<string, HTMLElement>());
  const [centers, setCenters] = useState<Record<string, number>>({});
  const [height, setHeight] = useState(0);

  useLayoutEffect(() => {
    const box = boxRef.current;
    if (!box) return;
    const read = () => {
      const top = box.getBoundingClientRect().top;
      const next: Record<string, number> = {};
      for (const [key, el] of rowRefs.current) {
        const r = el.getBoundingClientRect();
        next[key] = r.top - top + r.height / 2;
      }
      const h = Math.round(box.getBoundingClientRect().height);
      setCenters((have) => (JSON.stringify(have) === JSON.stringify(next) ? have : next));
      setHeight((have) => (have === h ? have : h));
    };
    read();
    if (typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(read);
    observer.observe(box);
    return () => observer.disconnect();
  });

  /** The attacks from one column to the next, once each. */
  const between = (from: P[], to: P[]) => {
    const a = new Set(from.map((p) => p.machineKey));
    const b = new Set(to.map((p) => p.machineKey));
    const seen = new Set<string>();
    return lines.filter((e) => {
      const key = `${e.source}|${e.target}`;
      if (seen.has(key) || !a.has(e.source) || !b.has(e.target)) return false;
      seen.add(key);
      return true;
    });
  };

  const place = (p: P) => (
    <div
      key={p.machineKey}
      ref={(el) => {
        if (el) rowRefs.current.set(p.machineKey, el);
        else rowRefs.current.delete(p.machineKey);
      }}
    >
      {row(p)}
    </div>
  );

  const links = (drawn: L[]) => (
    <svg width={LINK_COLUMN} height={Math.max(height, 1)} aria-hidden className="overflow-visible">
      {drawn.map((e) => {
        const y1 = centers[e.source];
        const y2 = centers[e.target];
        if (y1 === undefined || y2 === undefined) return null;
        const solid = inside(e);
        const mid = LINK_COLUMN / 2;
        return (
          <path
            key={`${e.source}|${e.target}`}
            data-testid={`${testId}-line`}
            data-inside={solid}
            d={`M 0 ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${LINK_COLUMN} ${y2}`}
            fill="none"
            stroke={solid ? (color?.(e) ?? INSIDE_INK) : LOUD_INK}
            strokeWidth={solid ? 1.75 : 1.5}
            strokeDasharray={solid ? undefined : '4 4'}
            opacity={solid ? 0.8 : 0.95}
          />
        );
      })}
    </svg>
  );

  const three = further.length > 0;
  const columns = three
    ? `minmax(0,1fr) ${LINK_COLUMN}px minmax(0,1fr) ${LINK_COLUMN}px minmax(0,1fr)`
    : `minmax(0,1fr) ${LINK_COLUMN}px minmax(0,1fr)`;

  return (
    <div data-testid={`${testId}-picture`} className="mb-3">
      <div
        className="mb-1.5 grid gap-0 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint"
        style={{ gridTemplateColumns: columns }}
      >
        <span>Actors</span>
        <span />
        <span>Targets</span>
        {three && (
          <>
            <span />
            <span>Beyond the first target</span>
          </>
        )}
      </div>
      <div ref={boxRef} className="relative grid items-start" style={{ gridTemplateColumns: columns }}>
        <fieldset data-testid={`${testId}-actors`} className="flex min-w-0 flex-col gap-1.5">
          <legend className="sr-only">Actors</legend>
          {actors.map(place)}
        </fieldset>
        {links(between(actors, targets))}
        <fieldset data-testid={`${testId}-targets`} className="flex min-w-0 flex-col gap-1.5">
          <legend className="sr-only">Targets</legend>
          {targets.map(place)}
        </fieldset>
        {three && (
          <>
            {links(between(targets, further))}
            <fieldset data-testid={`${testId}-further`} className="flex min-w-0 flex-col gap-1.5">
              <legend className="sr-only">Beyond the first target</legend>
              {further.map(place)}
            </fieldset>
          </>
        )}
      </div>
      {legend}
    </div>
  );
}
