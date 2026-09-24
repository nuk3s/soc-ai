// Frame 7 of the approved mockup is the tooltip copy. Every chip, pill, badge
// and status on the Hunts surfaces states what it means in one sentence, and
// three merges put those sentences on screen. One copy of the words keeps the
// three from drifting, so this test pins the words against the frame.
import { describe, expect, it } from 'vitest';

import {
  CHIP_ANALYTIC_MATCH,
  CHIP_CATALOG_RUN,
  CHIP_DISMISS_REASON,
  CHIP_LIVE,
  CHIP_LOCAL,
  CHIP_NO_BENIGN_BASELINE,
  CHIP_NO_LEAD,
  CHIP_ONE_SIGNAL_REPEATED,
  CHIP_RECORDED_IN_SHADOW,
  CHIP_SHADOW,
  CHIP_SHIPPED,
  CHIP_WINDOW,
  HIT_FILTERS,
  HIT_FILTER_ALL,
  HIT_FILTER_LIVE,
  HIT_FILTER_SHADOW,
  HIT_FILTER_UNREAD,
  PILL_DISMISSED,
  PILL_HUNTED,
  PILL_IN_PROGRESS,
  PILL_NEW,
  PILL_PROMOTED,
  STATUS_COMPLETE,
  STATUS_COULD_NOT_RUN,
  STATUS_RUNNING,
  TYPE_ALL,
  TYPE_CATALOG,
  TYPE_LEAD,
  TYPE_MANUAL,
  TYPE_SCHEDULE,
  UNREAD_DOT,
  chipNotApplicable,
  chipRead,
} from './tooltips';

describe('the lead pills', () => {
  it('states what each state means and what the analyst does next', () => {
    expect(PILL_NEW).toBe(
      'New: nobody has acted on this lead. Its hunt starts on its own, or hunt it by hand. ' +
        'Dismiss it if it is noise.',
    );
    expect(PILL_IN_PROGRESS).toBe(
      'In progress: a hunt is running on this lead. View the hunt to follow it.',
    );
    expect(PILL_HUNTED).toBe(
      'Hunted: the hunt on this lead finished. Read the hunt, then promote or dismiss the lead.',
    );
    expect(PILL_DISMISSED).toBe(
      'Dismissed: an analyst closed this lead with a reason. Reopen puts it back in the queue.',
    );
    expect(PILL_PROMOTED).toBe(
      'Promoted: an analyst opened an investigation from this lead. The lead is closed.',
    );
  });
});

describe('the analytic and hit chips', () => {
  it('states the status of the analytic and the tier it came from', () => {
    expect(CHIP_LIVE).toBe('Live: the analytic runs on every sweep. Its hits count and can form leads.');
    expect(CHIP_SHADOW).toBe(
      'Shadow: the analytic runs on every sweep, and its hits are recorded and shown. ' +
        'It raises nothing. Approve it to make it live.',
    );
    expect(CHIP_LOCAL).toBe('Local: a row in this deployment, written or drafted here.');
    expect(CHIP_SHIPPED).toBe('Shipped: a file in the soc-ai release.');
  });

  // The row flag holds the status of the last sighting, so a hit of an approved
  // analytic lists under Shadow with a live analytic above it. The chip states
  // that in one sentence instead of leaving the analyst to work it out.
  it('states where a hit was recorded when the analytic has moved on', () => {
    expect(CHIP_RECORDED_IN_SHADOW).toBe(
      'This hit was recorded while the analytic was in shadow. The analytic is live now.',
    );
  });

  it('states the lead chips and the hit chips', () => {
    expect(CHIP_ANALYTIC_MATCH).toBe('An analytic matched documents on this entity.');
    expect(CHIP_ONE_SIGNAL_REPEATED).toBe(
      'One type of observation repeated until its weight reached the single-signal threshold.',
    );
    expect(CHIP_NO_BENIGN_BASELINE).toBe(
      'No benign population produces this. One observation is a finding on its own.',
    );
    expect(CHIP_NO_LEAD).toBe('This hit formed no lead and joined none.');
    expect(CHIP_CATALOG_RUN).toBe('A row the catalog sweep wrote for an analytic hit. Not an agent run.');
    expect(CHIP_DISMISS_REASON).toBe('The dismissal reason the analyst chose.');
    expect(CHIP_WINDOW).toBe('The window the hunt searched.');
  });

  it('names the time on the read chip, and states the read without one', () => {
    expect(chipRead('2h ago')).toBe(
      "An analyst opened this hit's evidence or acted on it 2h ago.",
    );
    expect(chipRead()).toBe("An analyst opened this hit's evidence or acted on it.");
  });

  it('counts the starters that do not apply', () => {
    expect(chipNotApplicable(2)).toBe('2 starters do not match the telemetry this grid sees.');
    expect(chipNotApplicable(1)).toBe('1 starter does not match the telemetry this grid sees.');
  });
});

describe('the filters and the statuses', () => {
  it('states each hit filter on its own chip and all of them together', () => {
    expect(HIT_FILTER_ALL).toBe('Every hit from the last 7 days.');
    expect(HIT_FILTER_UNREAD).toBe('Shadow hits nobody has opened or acted on.');
    expect(HIT_FILTER_LIVE).toBe('Hits from live analytics. They count and can form leads.');
    expect(HIT_FILTER_SHADOW).toBe(
      'Hits from analytics in shadow. Recorded and shown. They raise nothing.',
    );
    expect(HIT_FILTERS).toBe(
      'Hit filters. Unread: shadow hits nobody has opened or acted on. ' +
        'Live: hits from live analytics. Shadow: hits from analytics in shadow.',
    );
  });

  it('states each hunt type', () => {
    expect(TYPE_ALL).toBe('Every hunt an agent ran.');
    expect(TYPE_MANUAL).toBe('Hunts an analyst started from an objective.');
    expect(TYPE_SCHEDULE).toBe('Hunts a schedule started.');
    expect(TYPE_LEAD).toBe('Hunts started from a lead.');
    expect(TYPE_CATALOG).toBe('Rows the catalog sweep wrote. Recorded before this release.');
  });

  it('states each hunt status and the unread dot', () => {
    expect(STATUS_RUNNING).toBe('The hunt is running now.');
    expect(STATUS_COMPLETE).toBe('The hunt finished. The findings column counts its threat findings.');
    expect(STATUS_COULD_NOT_RUN).toBe('The hunt could not run. The row names the reason.');
    expect(UNREAD_DOT).toBe('Unread. Open the evidence or act on the hit to mark it read.');
  });
});

import * as TIP from './tooltips';

// The mockup's Frame 7 is the copy. A chip that reads one way on the Hunts tab
// and another way on the lead page is two products, so every surface reads the
// same sentence from this one file.
describe('tooltips', () => {
  it('carries the Frame 7 sentence for every pill', () => {
    expect(TIP.PILL_NEW).toBe(
      'New: nobody has acted on this lead. Its hunt starts on its own, or hunt it by hand. ' +
        'Dismiss it if it is noise.',
    );
    expect(TIP.PILL_IN_PROGRESS).toBe(
      'In progress: a hunt is running on this lead. View the hunt to follow it.',
    );
    expect(TIP.PILL_HUNTED).toBe(
      'Hunted: the hunt on this lead finished. Read the hunt, then promote or dismiss the lead.',
    );
    expect(TIP.PILL_DISMISSED).toBe(
      'Dismissed: an analyst closed this lead with a reason. Reopen puts it back in the queue.',
    );
    expect(TIP.PILL_PROMOTED).toBe(
      'Promoted: an analyst opened an investigation from this lead. The lead is closed.',
    );
  });

  it('carries the Frame 7 sentence for every chip', () => {
    expect(TIP.CHIP_LIVE).toBe(
      'Live: the analytic runs on every sweep. Its hits count and can form leads.',
    );
    expect(TIP.CHIP_SHADOW).toBe(
      'Shadow: the analytic runs on every sweep, and its hits are recorded and shown. ' +
        'It raises nothing. Approve it to make it live.',
    );
    expect(TIP.CHIP_RECORDED_IN_SHADOW).toBe(
      'This hit was recorded while the analytic was in shadow. The analytic is live now.',
    );
    expect(TIP.CHIP_LOCAL).toBe('Local: a row in this deployment, written or drafted here.');
    expect(TIP.CHIP_SHIPPED).toBe('Shipped: a file in the soc-ai release.');
    expect(TIP.CHIP_ANALYTIC_MATCH).toBe('An analytic matched documents on this entity.');
    expect(TIP.CHIP_NO_LEAD).toBe('This hit formed no lead and joined none.');
    expect(TIP.CHIP_CATALOG_RUN).toBe(
      'A row the catalog sweep wrote for an analytic hit. Not an agent run.',
    );
    expect(TIP.CHIP_DISMISS_REASON).toBe('The dismissal reason the analyst chose.');
    expect(TIP.UNREAD_DOT).toBe('Unread. Open the evidence or act on the hit to mark it read.');
  });

  it('carries the Frame 7 sentence for every status word', () => {
    expect(TIP.STATUS_RUNNING).toBe('The hunt is running now.');
    expect(TIP.STATUS_COMPLETE).toBe(
      'The hunt finished. The findings column counts its threat findings.',
    );
    expect(TIP.STATUS_COULD_NOT_RUN).toBe('The hunt could not run. The row names the reason.');
  });

  it('gives one status sentence per hunt status', () => {
    expect(TIP.huntStatusTitle('running')).toBe(TIP.STATUS_RUNNING);
    expect(TIP.huntStatusTitle('complete')).toBe(TIP.STATUS_COMPLETE);
    expect(TIP.huntStatusTitle('error')).toBe(TIP.STATUS_COULD_NOT_RUN);
    expect(TIP.huntStatusTitle('cancelled')).toBe(TIP.STATUS_COULD_NOT_RUN);
    expect(TIP.huntStatusTitle('interrupted')).toBe(TIP.STATUS_COULD_NOT_RUN);
  });

  // A sentence that states nothing is a tooltip an analyst reads once. Every
  // sentence is one line, and it ends like a sentence.
  //
  // The floor is a proxy for "not a fragment", and 20 characters is a whole
  // short sentence: "Expand this section." is exactly that long and states the
  // act, the thing and nothing else.
  it('states one sentence per chip', () => {
    for (const [name, value] of Object.entries(TIP)) {
      if (typeof value !== 'string') continue;
      expect(value.length, name).toBeGreaterThanOrEqual(20);
      expect(value.includes('\n'), name).toBe(false);
      expect(/[.:]$/.test(value), name).toBe(true);
    }
  });
});
