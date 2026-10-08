import { Check, ChevronRight } from 'lucide-react';
import { Link } from 'react-router-dom';

import { cn } from '../lib/cn';
import type { FlowStep, FlowStepState } from '../lib/flowSteps';

// ---------------------------------------------------------------------------
// The flow strip: one line under the page header that names where this object
// sits in the flow, and what moves it on.
//
// The owner asked "What is the user flow?" (2026-10-07). The pages showed one
// object each and no chain between them. The strip names each step with a
// short noun and a state. A done step links to its object. The current step is
// the object on this page. The next step names the control that moves the flow
// to it. The steps come from lib/flowSteps.ts, which reads the stored fields.
//
// The strip wraps on a narrow window. It never cuts a word, so it carries no
// truncate class and no ellipsis.
// ---------------------------------------------------------------------------

/** The word a screen reader states after each step. */
const STATE_WORD: Record<FlowStepState, string> = {
  done: 'done',
  current: 'current step',
  next: 'next',
  not_yet: 'not yet',
};

/** The hover of each state, when the step carries no sentence of its own. */
function stepTitle(step: FlowStep): string | undefined {
  if (step.title) return step.title;
  if (step.state === 'next' && step.control) return `Next. ${step.control} moves the flow to this step.`;
  return undefined;
}

const BASE = 'inline-flex flex-wrap items-center gap-x-1 rounded-chip border px-1.5 py-px';

const STATE_CLASS: Record<FlowStepState, string> = {
  done: 'border-transparent text-text-2',
  current: 'border-accent bg-[rgba(75,139,245,.12)] font-semibold text-text',
  next: 'border-dashed border-accent/60 text-text-2',
  not_yet: 'border-transparent text-faint',
};

function StepBody({ step }: { step: FlowStep }) {
  const label =
    step.to && step.state !== 'not_yet' ? (
      <Link to={step.to} className="text-accent hover:underline">
        {step.label}
      </Link>
    ) : (
      <span>{step.label}</span>
    );
  return (
    <>
      {step.state === 'done' && <Check size={11} aria-hidden className="flex-none text-success" />}
      {label}
      {step.note && <span className="font-normal text-dim">{step.note}</span>}
      {step.state === 'next' && step.control && (
        <span data-testid={`flow-control-${step.key}`} className="font-semibold text-accent">
          {`· ${step.control}`}
        </span>
      )}
      <span className="sr-only">{`, ${STATE_WORD[step.state]}`}</span>
    </>
  );
}

export interface FlowStripProps {
  /** The steps, in order. Build them with lib/flowSteps.ts. */
  steps: FlowStep[];
  /** The name a screen reader states for the strip. */
  label?: string;
  className?: string;
}

/** One line of steps. Each step is a short noun with a state. */
export function FlowStrip({ steps, label = 'The flow', className }: FlowStripProps) {
  if (steps.length === 0) return null;
  return (
    <nav aria-label={label} data-testid="flow-strip" className={cn('text-[11.5px] leading-[1.6]', className)}>
      <ol className="flex flex-wrap items-center gap-x-1 gap-y-1">
        {steps.map((step, i) => (
          <li
            key={step.key}
            data-testid={`flow-step-${step.key}`}
            data-state={step.state}
            aria-current={step.state === 'current' ? 'step' : undefined}
            title={stepTitle(step)}
            className="inline-flex items-center gap-x-1"
          >
            {i > 0 && <ChevronRight size={12} aria-hidden className="flex-none text-ghost" />}
            <span className={cn(BASE, STATE_CLASS[step.state])}>
              <StepBody step={step} />
            </span>
          </li>
        ))}
      </ol>
    </nav>
  );
}
