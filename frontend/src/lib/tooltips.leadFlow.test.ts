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
        'lead with no documents. You decide what the hunt found.',
    );
    expect(TIP.ACTION_HUNT_NOW).toBe('Start the hunt now. The lead does not wait for the loop.');
  });

  // The note states the exclusions, and the lead that carries one states it on
  // the row. An analyst who read the note over a shadow lead waited for a hunt
  // that never came.
  it('states why the loop leaves one lead alone', () => {
    expect(TIP.CHIP_LEFT_TO_YOU).toBe(
      'The loop starts no hunt here: a shadow lead, a reopened lead, or a lead with no ' +
        'documents. Hunt it by hand.',
    );
  });
});

describe('a hunt is the subject of an investigation', () => {
  it('states why Promote waits on a hunt', () => {
    expect(TIP.PROMOTE_NEEDS_HUNT).toBe(
      "Hunt this lead first. The investigation reads the hunt's findings.",
    );
  });

  // The chip on the Investigations list read "The detector that raised this
  // alert, as the grid names it." over a row that no detector raised.
  it('states what a lead run and a hunt run are, on the type chip', () => {
    expect(TIP.detectionKindTitle('lead')).toBe(
      "An investigation that started from a lead. Its subject is the lead's hunt.",
    );
    expect(TIP.detectionKindTitle('hunt')).toBe(
      "An investigation that started from a hunt. Its subject is the hunt's findings.",
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
      "An investigation of a hunt. The subject is the hunt's findings, not one event.",
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
