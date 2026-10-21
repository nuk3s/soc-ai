// Dogfood 2026-10-19, R2-D15 and STE items 21 and 22: a second press did not
// say what remained. "Acknowledged 0 alerts across 1 group" wore a green check,
// and "Opened no cases for ET TOR ..." named no case. The server now counts the
// handled alerts on a second press and lists the cases they are on, so the
// sentence can name them.
import { describe, expect, it } from 'vitest';
import type { AckGroupResult, EscalateGroupResult } from './api';
import {
  ackMessage,
  ackWroteNothing,
  escalateLinks,
  escalateMessage,
  escalateWroteNothing,
} from './groupWriteMessages';

const ack = (o: Partial<AckGroupResult>): AckGroupResult => ({
  acked: 0,
  failed: 0,
  total: 0,
  capped: false,
  already_acked: 0,
  remaining: 0,
  ...o,
});

const esc = (o: Partial<EscalateGroupResult>): EscalateGroupResult => ({
  escalated: 0,
  failed: 0,
  total: 0,
  capped: false,
  already_escalated: 0,
  already_acked: 0,
  unresolved: 0,
  remaining: 0,
  ...o,
});

describe('a second acknowledge press', () => {
  it('says the alerts are already acknowledged and that soc-ai wrote nothing', () => {
    const r = ack({ already_acked: 2 });
    expect(ackWroteNothing(r)).toBe(true);
    expect(ackMessage(r, 'ET INFO Java')).toBe(
      'The 2 alerts of ET INFO Java are already acknowledged. soc-ai wrote nothing.',
    );
  });

  it('uses the singular for one alert', () => {
    expect(ackMessage(ack({ already_acked: 1 }), 'ET INFO Java')).toBe(
      'The alert of ET INFO Java is already acknowledged. soc-ai wrote nothing.',
    );
  });

  it('says why the rows stay when the index of the detection cannot hide them', () => {
    expect(ackMessage(ack({ already_acked: 17 }), 'Curl', { unhidable: true })).toBe(
      'The 17 alerts of Curl are already acknowledged. soc-ai wrote nothing. ' +
        'The index of this detection cannot hide them. They stay listed.',
    );
  });

  it('says so when nothing waits and nothing was handled', () => {
    expect(ackMessage(ack({}), 'ET INFO Java')).toBe(
      'No alert of ET INFO Java waits for an acknowledgement. soc-ai wrote nothing.',
    );
  });

  it('NEGATIVE CONTROL: a press that wrote keeps the old sentence', () => {
    const r = ack({ acked: 12, total: 12 });
    expect(ackWroteNothing(r)).toBe(false);
    expect(ackMessage(r, 'ET INFO Java')).toBe('Acknowledged 12 alerts in ET INFO Java');
  });

  it('NEGATIVE CONTROL: a press where every write failed is not "wrote nothing"', () => {
    expect(ackWroteNothing(ack({ failed: 2, total: 2 }))).toBe(false);
  });
});

describe('a second escalate press', () => {
  it('names the case the alert is already on', () => {
    const r = esc({ already_escalated: 1, existing_cases: [{ id: 'case-tor-1', url: null }] });
    expect(escalateWroteNothing(r)).toBe(true);
    expect(escalateMessage(r, 'ET TOR Known Tor Exit Node')).toBe(
      'The alert of ET TOR Known Tor Exit Node is already on case case-tor-1. soc-ai opened no case.',
    );
  });

  it('names the cases of a group of several alerts without pinning each alert to one', () => {
    const r = esc({
      already_escalated: 3,
      existing_cases: [
        { id: 'c-1', url: null },
        { id: 'c-2', url: null },
      ],
    });
    expect(escalateMessage(r, 'ET TOR')).toBe(
      'The 3 alerts of ET TOR are already on a case. The soc-ai record names cases c-1, c-2. soc-ai opened no case.',
    );
  });

  it('says "a case" when the soc-ai record has no case id', () => {
    expect(escalateMessage(esc({ already_escalated: 1 }), 'ET TOR')).toBe(
      'The alert of ET TOR is already on a case. soc-ai opened no case.',
    );
  });

  it('keeps the escalated and the acknowledged alerts apart', () => {
    expect(
      escalateMessage(
        esc({ already_escalated: 1, already_acked: 17, existing_cases: [{ id: 'c-9', url: null }] }),
        'ET TOR',
      ),
    ).toBe(
      '1 alert of ET TOR is already on case c-9. 17 alerts of ET TOR are already acknowledged. soc-ai opened no case.',
    );
  });

  it('says what remains for a further press', () => {
    expect(escalateMessage(esc({ already_acked: 2, remaining: 30, capped: true }), 'ET TOR')).toBe(
      '2 alerts of ET TOR are already acknowledged. soc-ai opened no case. 30 alerts left. Press again to continue.',
    );
  });

  it('says so when no alert waits for a case', () => {
    expect(escalateMessage(esc({}), 'ET TOR')).toBe(
      'No alert of ET TOR waits for a case. soc-ai opened no case.',
    );
  });

  it('links the existing case when Security Onion gives a URL', () => {
    const r = esc({
      already_escalated: 1,
      existing_cases: [{ id: 'case-tor-1', url: 'https://so.example.test/#/case/case-tor-1' }],
    });
    expect(escalateLinks(r)).toEqual([
      { label: 'Open case case-tor-1', href: 'https://so.example.test/#/case/case-tor-1' },
    ]);
  });

  it('names the existing case beside a press that opened another', () => {
    const r = esc({
      escalated: 1,
      total: 1,
      already_escalated: 2,
      cases: [{ id: 'c-new', url: null }],
      existing_cases: [{ id: 'c-old', url: null }],
    });
    expect(escalateWroteNothing(r)).toBe(false);
    expect(escalateMessage(r, 'ET TOR')).toBe(
      'Opened 1 case for ET TOR: c-new · 2 alerts already on a case, no second case opened · Existing case: c-old',
    );
  });

  it('NEGATIVE CONTROL: an empty case is a failure, not "wrote nothing"', () => {
    const r = esc({ failed: 1, total: 1, empty_cases: ['case-9f3'] });
    expect(escalateWroteNothing(r)).toBe(false);
    expect(escalateMessage(r, 'ET TOR')).toMatch(/^Opened no cases for ET TOR/);
  });

  it('NEGATIVE CONTROL: a clean press says only what happened', () => {
    expect(escalateMessage(esc({ escalated: 2, total: 2 }), 'GPL ICMP')).toBe('Opened 2 cases for GPL ICMP');
  });
});
