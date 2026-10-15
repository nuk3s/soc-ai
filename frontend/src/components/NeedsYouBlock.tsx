import { Link } from 'react-router-dom';

import { type NeedsYouState, needsYouLines } from '../lib/needsYou';
import { LoadingInline } from './States';

/**
 * The Needs-you block of the bell panel and the Notifications screen.
 *
 * One line per part of the needs-you count that is not zero: the count, a
 * plain noun and the scope of the count in words, with a link to the list that
 * holds the part. The lines add up to the bell badge. The badge read 309 over a
 * panel of 12 shadow hits, and nothing on the panel said what the other 297
 * were (production 2026-10-14).
 *
 * A part the server could not read keeps its line and says so, as the badge's
 * "+" does. `onFollow` runs when a link is followed, so the bell can close.
 */
export function NeedsYouBlock({
  state,
  onFollow,
  className = '',
}: {
  state: NeedsYouState;
  onFollow?: () => void;
  className?: string;
}) {
  const { data, failed } = state;
  const lines = needsYouLines(data);
  return (
    <div data-testid="needs-you-block" className={className}>
      <div className="text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">Needs you</div>
      <div className="mt-1 text-[12px] leading-[1.5] text-dim">
        {!data ? (
          failed ? (
            'Could not read what needs you.'
          ) : (
            <LoadingInline>Reading what needs you</LoadingInline>
          )
        ) : lines.length === 0 ? (
          'Nothing needs you.'
        ) : (
          <ul className="flex flex-col gap-0.5">
            {lines.map((line) => (
              <li key={line.key} data-testid={`needs-you-part-${line.key}`}>
                {line.count === null ? (
                  <span className="text-faint">{line.unknown}</span>
                ) : (
                  <>
                    <Link to={line.to} onClick={onFollow} className="text-accent hover:underline">
                      {line.text}
                    </Link>
                    <span className="text-faint">, {line.scope}</span>
                  </>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
