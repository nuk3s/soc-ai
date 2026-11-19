import { Radar } from 'lucide-react';
import { Link } from 'react-router-dom';
import { HUNT_ANSWER_TITLE, huntAnswerSentence } from '../../lib/campaignWords';

/** The tone of an answer: new activity is an alarm, the other two are calm. */
export function huntAnswerTone(outcome: string): string {
  return outcome === 'new_activity' ? 'rgb(var(--danger))' : 'rgb(var(--text-2))';
}

/** The newest answer of a hunt that read a campaign or a lead, as one line
 *  with a mark: the hunt, the time and what it found. The line links to the
 *  hunt. Nothing renders with no answer. `later` states the later alert
 *  events of a campaign after the answer (G6). */
export function HuntAnswerLine({
  subject,
  answer,
  testId,
  className = '',
  later = null,
}: {
  subject: 'campaign' | 'lead';
  answer: { huntId: string; outcome: string; huntAt: string | null; findingTitle: string | null } | null | undefined;
  testId: string;
  className?: string;
  later?: string | null;
}) {
  if (!answer) return null;
  const tone = huntAnswerTone(answer.outcome);
  return (
    <div
      data-testid={testId}
      data-outcome={answer.outcome}
      title={HUNT_ANSWER_TITLE}
      className={`flex items-start gap-2 text-[12.5px] leading-snug text-text-2 ${className}`}
    >
      <Radar size={14} aria-hidden className="mt-px flex-none" style={{ color: tone }} />
      <span className="min-w-0 break-words">
        <span className={answer.outcome === 'new_activity' ? 'font-semibold text-text' : undefined}>
          {huntAnswerSentence(subject, answer)}
        </span>{' '}
        {later && (
          <>
            <span data-testid={`${testId}-later`}>{later}</span>{' '}
          </>
        )}
        <Link to={`/hunts/${encodeURIComponent(answer.huntId)}`} className="text-accent hover:underline">
          Open the hunt
        </Link>
      </span>
    </div>
  );
}
