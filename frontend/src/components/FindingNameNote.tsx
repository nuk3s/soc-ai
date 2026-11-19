import { AlertTriangle } from 'lucide-react';

/** The note of a finding whose text names a known machine that is no host of
 *  the finding (dogfood 2026-11-17, AA2). The server writes the words, so the
 *  campaign page and the investigation page state the same note. */
export function FindingNameNote({ note, className = '' }: { note?: string | null; className?: string }) {
  if (!note) return null;
  return (
    <div
      data-testid="finding-name-note"
      className={`flex items-start gap-1.5 text-[11.5px] leading-[1.45] text-warn ${className}`}
    >
      <AlertTriangle size={13} aria-hidden className="mt-px flex-none" />
      <span>{note}</span>
    </div>
  );
}
