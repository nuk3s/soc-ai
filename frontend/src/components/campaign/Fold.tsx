import { useId, type ReactNode, type Ref } from 'react';
import { AlertTriangle } from 'lucide-react';
import { CollapseChevron, Panel } from '../Panel';

/** One table of the campaign page under the graphics, as one panel. The
 *  header row is one button: the chevron, the title and the count. The
 *  content renders only when the fold is open. The page decides when a fold
 *  has nothing to show and does not render it. */
export function Fold({
  title,
  count,
  detail,
  open,
  onToggle,
  testId,
  foldRef,
  tone,
  children,
}: {
  title: string;
  /** The count after the title. Null shows no count. */
  count: number | null;
  /** The counts in words after the title, for a fold of two lists: "2 leads, 3 hunts". */
  detail?: string;
  open: boolean;
  onToggle: () => void;
  testId: string;
  foldRef?: Ref<HTMLDivElement>;
  /** `danger`: the fold is an alarm. Its title and its border wear the danger tone. */
  tone?: 'danger';
  children: ReactNode;
}) {
  const bodyId = useId();
  const danger = tone === 'danger';
  return (
    <div ref={foldRef} data-testid={testId} data-open={open} data-tone={tone}>
      <Panel className={danger ? 'border-danger/55' : undefined}>
        <CollapseChevron
          collapsed={!open}
          onToggle={onToggle}
          // The name states the action and the fold: "Expand Members". The
          // shared tooltip says a fold stays closed on this browser, and these
          // folds do not, so the button sets its own name and no tooltip.
          label={`${open ? 'Collapse' : 'Expand'} ${title}`}
          controls={open ? bodyId : undefined}
          className="flex w-full items-center gap-[9px] px-[15px] py-3 text-left"
        >
          {danger && <AlertTriangle size={14} aria-hidden className="flex-none text-danger" />}
          <span className={`text-[13px] font-semibold ${danger ? 'text-danger' : 'text-text'}`}>{title}</span>
          {count !== null && (
            <span data-testid={`${testId}-count`} className="font-mono text-[11.5px] tabular-nums text-faint">
              {count.toLocaleString()}
            </span>
          )}
          {detail && (
            <span data-testid={`${testId}-detail`} className="text-[11.5px] text-faint">
              {detail}
            </span>
          )}
        </CollapseChevron>
        {open && (
          <div id={bodyId} className="border-t border-border">
            {children}
          </div>
        )}
      </Panel>
    </div>
  );
}
