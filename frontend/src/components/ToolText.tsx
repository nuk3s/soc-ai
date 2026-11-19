import { Fragment } from 'react';
import { toolSegments } from '../lib/headline';

/** Prose with each tool id that it names in the words of the one label map
 *  (lib/toolLabels). The tooltip keeps what the model wrote: a finding read
 *  "t_beacon_profile flagged 5 external pairs" (dogfood 2026-11-17, F20). */
export function ToolText({ text }: { text: string }) {
  return (
    <>
      {toolSegments(text).map((seg, i) =>
        seg.tool ? (
          <span
            key={i}
            data-testid="tool-words"
            title={`The model named the tool: ${seg.tool}`}
            className="underline decoration-dotted decoration-1 underline-offset-2"
          >
            {seg.text}
          </span>
        ) : (
          <Fragment key={i}>{seg.text}</Fragment>
        ),
      )}
    </>
  );
}
