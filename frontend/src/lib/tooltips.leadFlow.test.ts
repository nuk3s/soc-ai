// The four decisions of the 2026-09-22 design put new words on the screen: a
// queued hunt, a hunt as the subject of an investigation, a related lead, and
// the table that says whether the lead rule earns its place.
//
// Each word states what it means in one sentence, and every sentence lives in
// `lib/tooltips.ts`. The strip, the lead page, the investigation page and the
// Analytics tab all read from there, so one word cannot mean two things.
import { describe, expect, it } from 'vitest';

import * as TIP from './tooltips';

describe('a lead starts its own hunt', () => {
  it('states that a queued hunt waits on the loop and not on the analyst', () => {
    expect(TIP.PILL_HUNT_QUEUED).toBe(
      "The lead's hunt starts within a minute. Nothing waits on you yet.",
    );
    expect(TIP.LEGEND_AUTO_HUNT).toBe('A new lead starts its own hunt.');
    expect(TIP.LEADS_NOTE_AUTO_HUNT).toBe(
      'soc-ai starts a hunt on every new lead, except a shadow lead, a reopened lead and a ' +
        'lead with no documents. A shadow lead comes from a shadow analytic. ' +
        'You decide what the hunt found.',
    );
    expect(TIP.ACTION_HUNT_NOW).toBe('Start the hunt now. The lead does not wait for auto-hunt.');
  });

  // The note states the exclusions, and the lead that carries one states it on
  // the row. An analyst who read the note over a shadow lead waited for a hunt
  // that never came. "The loop" is code vocabulary. The setting is auto-hunt.
  it('states why auto-hunt leaves one lead alone', () => {
    expect(TIP.CHIP_LEFT_TO_YOU).toBe(
      'Auto-hunt starts no hunt here: a shadow lead, a reopened lead, or a lead with no ' +
        'documents. A shadow lead comes from a shadow analytic. Hunt it by hand.',
    );
  });
});

describe('a hunt is the subject of an investigation', () => {
  // The owner could not tell a hunt from an investigation (2026-10-07). The
  // hunt button says what a hunt returns and what it does not do.
  it('states what a hunt returns, and that it takes no action', () => {
    expect(TIP.ACTION_HUNT).toBe(
      'Start a hunt on this lead. The hunt returns findings and a narrative. soc-ai investigates ' +
        'each threat finding and shows the verdicts. The hunt takes no action in Security Onion.',
    );
    expect(TIP.LEAD_ACTIONS_LINE).toBe(
      'Hunt this lead. soc-ai investigates each threat finding of the hunt and shows the verdicts.',
    );
    expect(TIP.ACTION_OPEN_INVESTIGATION).toBe(
      'Open an investigation on this finding. The control starts one run of the model on the ' +
        'evidence that the finding cites. The run ends in a verdict and recommended actions.',
    );
    expect(TIP.DEFINE_HUNT).toContain('soc-ai investigates each threat finding when the hunt ends.');
    // Negative control: no sentence offers "promote" as an act.
    for (const s of [TIP.ACTION_HUNT, TIP.LEAD_ACTIONS_LINE, TIP.DEFINE_LEAD, TIP.DEFINE_HUNT]) {
      expect(s).not.toMatch(/promot/i);
    }
  });

  // The chip on the Investigations list read "The detector that raised this
  // alert, as the grid names it." over a row that no detector raised.
  it('states what a lead run and a hunt run are, on the type chip', () => {
    expect(TIP.detectionKindTitle('lead')).toBe(
      "An investigation that started from a lead. Its subject is the lead's hunt.",
    );
    // Change E. A finding run judges one finding, and a lead run or an older
    // finding run judges the whole hunt. The list row cannot tell them apart,
    // so the sentence is true for both.
    expect(TIP.detectionKindTitle('hunt')).toBe(
      'An investigation that started from a hunt. Its subject is one finding of the hunt or ' +
        'the whole hunt.',
    );
  });

  // The other three chips name a detector, because a detector raised the
  // alert the run started from.
  it('keeps the detector sentence for the detectors', () => {
    expect(TIP.detectionKindTitle('suricata')).toBe(
      'Suricata raised this alert. It reads network traffic.',
    );
    expect(TIP.detectionKindTitle('sigma')).toBe(
      'A Sigma rule raised this alert. It reads host and application logs.',
    );
    expect(TIP.detectionKindTitle('notice')).toBe(
      'Zeek raised this notice. It reads network traffic.',
    );
  });

  it('states what the subject of a hunt investigation is', () => {
    expect(TIP.CHIP_SUBJECT_HUNT).toBe(
      'An investigation of a hunt. Its subject is one finding of the hunt or the whole hunt.',
    );
    expect(TIP.SUBJECT_OBJECTIVE).toBe(
      'The objective the hunt ran with. This investigation answers it.',
    );
    expect(TIP.SUBJECT_FINDINGS).toBe('The findings of the hunt this investigation read.');
    expect(TIP.SUBJECT_DOCUMENTS).toBe(
      'The documents the findings cite. The investigation read every one of them.',
    );
    expect(TIP.SUBJECT_HUNT_LINK).toBe('Open the hunt this investigation read.');
    expect(TIP.SUBJECT_LEAD).toBe(
      'The lead this hunt started from. Open it to read its observations.',
    );
    // Change E. A new finding run judges one finding, and the hunt is context.
    expect(TIP.SUBJECT_FINDING).toBe(
      'The finding this investigation judges. The rest of the hunt is context.',
    );
    expect(TIP.SUBJECT_HUNT_CONTEXT).toBe(
      'The hunt this finding came from. The investigation read it as context.',
    );
    expect(TIP.SUBJECT_OBJECTIVE_CONTEXT).toBe(
      'The objective the hunt ran with. It is context for the finding.',
    );
  });
});

describe('leads relate', () => {
  // The code joins two leads on four things. The sentences named three, and
  // the reason an analyst read on the range was the fourth.
  it('states the window and the four things two leads can share', () => {
    expect(TIP.CHIP_RELATED).toBe(
      'Open leads from the last 7 days that share an analytic, an alert rule, an external ' +
        'address or a technique with this one.',
    );
    expect(TIP.RELATED_REASON).toBe(
      'What the two leads share: an analytic, an alert rule, an external address or a technique.',
    );
  });
});

describe('the lead quality block', () => {
  it('states what every column of the week table counts', () => {
    expect(TIP.LEAD_QUALITY).toBe(
      'What the lead rule produced: leads formed, hunted, promoted and dismissed.',
    );
    expect(TIP.QUALITY_WEEK).toBe('The week the leads formed in. Each row counts that week alone.');
    expect(TIP.QUALITY_FORMED).toBe('Leads that formed in the week.');
    expect(TIP.QUALITY_HUNTED).toBe('Leads from the week that a hunt has run on.');
    expect(TIP.QUALITY_THREAT).toBe('Leads from the week whose hunt reported a threat finding.');
    expect(TIP.QUALITY_PROMOTED).toBe(
      'Leads from the week an analyst promoted to an investigation.',
    );
    expect(TIP.QUALITY_DISMISSED).toBe(
      'Leads from the week an analyst dismissed, under the reason the analyst chose.',
    );
  });

  it('states what every column of the type table counts', () => {
    expect(TIP.QUALITY_TYPES).toBe('The observation types that formed the lead, as one set.');
    expect(TIP.QUALITY_TYPES_FORMED).toBe('Leads these types formed over the window.');
    expect(TIP.QUALITY_TYPES_DISMISSED).toBe('Leads these types formed that an analyst dismissed.');
    expect(TIP.QUALITY_TYPES_THREAT).toBe(
      'Leads these types formed whose hunt reported a threat finding.',
    );
  });
});
