import { Link } from 'react-router-dom';

import {
  NEEDS_YOU_PAGE,
  type NeedsYouState,
  decisionCount,
  decisionFloor,
  needsYouLines,
  needsYouReviewLine,
} from '../lib/needsYou';
import { LoadingInline } from './States';

/**
 * The Needs-you block of the bell panel and the Notifications screen.
 *
 * One line per decision part of the needs-you count that is not zero: the
 * count, a plain noun and the scope of the count in words, with a link to the
 * list that holds the part. The lines add up to the bell badge. The badge read
 * 309 over a panel of 12 shadow hits, and nothing on the panel said what the
 * other 297 were (production 2026-10-14).
 *
 * The unread shadow hits are review work. They have their own line under the
 * decisions, in a neutral color, with their own link. They are not in the
 * badge (production review 2026-11-12, ui-core 4).
 *
 * A part the server could not read keeps its line and says so, as the badge's
 * "+" does. `onFollow` runs when a link is followed, so the bell can close.
 *
 * The heading links to the Needs you page, the one list of every decision,
 * and states the decision count of the bell badge.
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
  const review = needsYouReviewLine(data);
  return (
    <div data-testid="needs-you-block" className={className}>
      <Link
        to={NEEDS_YOU_PAGE}
        onClick={onFollow}
        data-testid="needs-you-page-link"
        title="Open the Needs you page"
        className="inline-flex items-baseline gap-1.5 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint hover:text-accent"
      >
        Needs you
        {data && (
          <span className="font-mono normal-case tracking-normal text-text-2">
            {`${decisionCount(data).toLocaleString()}${decisionFloor(data) ? '+' : ''}`}
          </span>
        )}
      </Link>
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
                    <span className="text-faint">
                      ,{' '}
                      <span data-testid="scope-of-part" className="whitespace-nowrap">
                        {line.scope}
                      </span>
                    </span>
                  </>
                )}
              </li>
            ))}
          </ul>
        )}
        {review && (
          <div data-testid="needs-you-review" className="mt-1">
            {review.count === null ? (
              <span className="text-faint">{review.unknown}</span>
            ) : (
              <>
                <Link to={review.to} onClick={onFollow} className="text-text-2 hover:underline">
                  {review.text}
                </Link>
                <span className="text-faint">, {review.scope}</span>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
