import { cn } from '../lib/cn';
import { LEADS_NOTE_AUTO_HUNT, LEAD_LEGEND, LEGEND_AUTO_HUNT } from '../lib/tooltips';
import { Definition } from './Definition';

// ---------------------------------------------------------------------------
// The policy of leads, behind one closed disclosure.
//
// Three grey paragraphs stated the policy of leads (what a lead is, the four
// states, who starts a hunt) on the Hunts page, the lead page and the host
// page, above the facts of each page (dogfood 2026-11-17, N8). The facts come
// first. The policy sits behind one closed disclosure with the same words on
// each page.
// ---------------------------------------------------------------------------

/** The summary of the disclosure. */
export const HOW_LEADS_WORK = 'How leads work';

/** The note on a deployment where auto-hunt is off. */
export const LEADS_NOTE_MANUAL = 'soc-ai records leads. It does not start a hunt from a lead by itself.';
const LEADS_NOTE_MANUAL_TITLE = `${LEADS_NOTE_MANUAL} An analyst starts every hunt from a lead in this release.`;

/** The four states of a lead, and the auto-hunt sentence when the loop runs. */
export function leadStatusLegend(autoHunt: boolean): string {
  return autoHunt ? `${LEAD_LEGEND} ${LEGEND_AUTO_HUNT}` : LEAD_LEGEND;
}

export function HowLeadsWork({
  autoHunt,
  className,
  legendTestId = 'leads-legend',
  noteTestId = 'leads-note',
}: {
  autoHunt: boolean;
  className?: string;
  legendTestId?: string;
  noteTestId?: string;
}) {
  return (
    <details data-testid="how-leads-work" className={cn('text-[11.5px] leading-[1.6] text-dim', className)}>
      <summary className="cursor-pointer select-none font-semibold text-text-2 hover:text-text">
        {HOW_LEADS_WORK}
      </summary>
      <div className="mt-1 flex flex-col gap-1">
        <Definition of="lead" />
        <p data-testid={legendTestId}>{leadStatusLegend(autoHunt)}</p>
        <p data-testid={noteTestId} title={autoHunt ? LEADS_NOTE_AUTO_HUNT : LEADS_NOTE_MANUAL_TITLE}>
          {autoHunt ? LEADS_NOTE_AUTO_HUNT : LEADS_NOTE_MANUAL}
        </p>
      </div>
    </details>
  );
}
