// Hunt detail rendering a CATALOG hunt — the declarative-spec path.
//
// A catalog hunt is produced by soc_ai/hunting/sweep.py: one Elasticsearch
// query per spec, no model call at any point. Its findings' words come from
// the spec's own YAML (soc_ai/hunting/findings.py composes them), so the page
// must never imply a model judged anything here. The fixture below is built
// from that real shape — `startedBy: 'hunt-catalog'` (SWEEP_ACTOR),
// `kind: 'triggered'`, and a `spec_report`-shaped report — not an invented one.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AboutInfo, HuntDetailData } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunt: vi.fn(),
  promoteFinding: vi.fn(),
  cancelHuntConsole: vi.fn(),
  deleteHunt: vi.fn(),
  startHuntConsole: vi.fn(),
  getHuntChat: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  postHuntChat: vi.fn(),
  getAbout: vi.fn(),
  draftFindingDetection: vi.fn(),
  getEvent: vi.fn(),
}));

import { getAbout, getEvent, getHunt } from '../lib/api';
import { ShellProvider } from '../shell/ShellContext';
import { HuntDetail } from './HuntDetail';

const about: AboutInfo = {
  version: '1.5.1',
  repo_url: 'https://example.test/soc-ai',
  license: 'MIT',
  update_check_enabled: false,
  general_chat_enabled: true,
  sigma_authoring_enabled: false,
};

const HUNT_ID = 'H-catalog-1';

// The spec's own description, collapsed to one line exactly as
// findings.py `_sentence()` does. Every number in it was measured by the
// author when the spec was written; none of it is a fact about this run.
const SPEC_PROSE =
  'An OpenCanary honeypot recorded an inbound interaction. Nothing has a legitimate ' +
  'reason to talk to a decoy: it advertises services that exist only to be touched, it ' +
  'is not in DNS, and no real workload routes to it. That property is why this spec is ' +
  'worth having even though the range currently holds only 14 documents. OpenCanary ' +
  'writes a logtype 1001 record every time the service starts, and on this range 8 of ' +
  'the 14 documents are exactly that. Interactions are distinguished by carrying a ' +
  'source address, which the boot record does not: measured here, 6 documents have ' +
  'source.ip, 8 do not.';

// ...and the tail candidate_findings() appends per candidate. This half IS
// this run: the doc count and the timestamps came out of the query.
const RUN_TAIL =
  'Matched 4 documents for ip 192.0.2.254 first at 2026-09-04T17:58:42.105Z, ' +
  'last at 2026-09-04T18:02:11.900Z.';

// execute.py caps top_hits at MAX_SAMPLE_IDS = 3 per bucket, so a candidate
// over 4 documents cites three ids. That cap is the whole reason the chip
// count and the narrative's document count disagree.
const CITATIONS = ['dGVsLWRvYy0x', 'dGVsLWRvYy0y', 'dGVsLWRvYy0z'];

const catalogFinding = {
  title: 'Something connected to a decoy service — 192.0.2.254',
  detail: `${SPEC_PROSE} ${RUN_TAIL}`,
  severity: 'high',
  category: 'threat',
  hosts: ['192.0.2.254'],
  citations: CITATIONS,
  // The seam, carried rather than guessed: findings.py knows where the
  // author's prose ends because it is the one that appended the rest.
  specRationale: SPEC_PROSE,
  matchedDocs: 4,
};

// The other half of the catalog's output, and the one the split never reached.
// A blind spec records this instead of a candidate: the run saw nothing at all,
// so the author's measurements are the only numbers in the paragraph and the
// only ones a reader can mistake for fresh.
const GAP_RUN_TAIL =
  'This spec found nothing, but it also could not see: its precondition matched no ' +
  'documents at all in the 90 days to 2026-09-05T12:00:00Z, so the telemetry it reads is ' +
  'absent from this grid rather than clean. Treat this as a coverage gap, not an all-clear.';

const gapFinding = {
  title: 'No telemetry for decoy-opencanary-interaction',
  detail: `${SPEC_PROSE} ${GAP_RUN_TAIL}`,
  severity: 'medium',
  category: 'visibility_gap',
  hosts: [],
  citations: [],
  specRationale: SPEC_PROSE,
};

function catalogHunt(over: Partial<HuntDetailData> = {}): HuntDetailData {
  return {
    id: HUNT_ID,
    objective:
      '[catalog] decoy-opencanary-interaction: Something connected to a decoy service ' +
      '(2026-09-04T12:00:00Z → 2026-09-05T12:00:00Z)',
    kind: 'triggered',
    status: 'complete',
    narrative:
      'Something connected to a decoy service: 1 finding(s) from 4 matching document(s) ' +
      'between 2026-09-04T12:00:00Z and 2026-09-05T12:00:00Z, with no model call.',
    findings: [catalogFinding],
    affectedHosts: ['192.0.2.254'],
    mitreTechniques: ['T1046', 'T1110'],
    recommendedActions: [],
    // spec_report() omits `confidence` entirely and the API preserves the
    // absence as null (routes_hunts.py `_report_confidence`). The page reads
    // the dial off this field, not off the actor.
    confidence: null,
    startedBy: 'hunt-catalog',
    elapsedLabel: '0s',
    elapsedSec: 0,
    ts: '2026-09-04T18:02:12Z',
    timeline: [],
    diff: null,
    ...over,
  };
}

function mount() {
  return render(
    <MemoryRouter initialEntries={[`/hunts/${HUNT_ID}`]}>
      <ShellProvider>
        <Routes>
          <Route path="/hunts/:id" element={<HuntDetail />} />
        </Routes>
      </ShellProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getAbout).mockResolvedValue(about);
  vi.mocked(getHunt).mockResolvedValue(catalogHunt());
});

describe('HuntDetail — a catalog hunt makes no model call', () => {
  it('renders no confidence dial, because nothing scored this hunt', async () => {
    mount();
    await screen.findByText(catalogFinding.title);
    // "0.00 CONFIDENCE" in 30px type next to MALICIOUS ACTIVITY FOUND reads as
    // "the system has zero confidence in this". Nothing scored it at all.
    expect(screen.queryByText('0.00')).toBeNull();
    expect(screen.queryByText(/^confidence$/i)).toBeNull();
    // Something honest in its place, not a silent gap. Anchored, so the
    // narrative's own "with no model call" sentence cannot satisfy it.
    expect(screen.getByText(/^no model call$/i)).toBeInTheDocument();
    // The noun is the taxonomy's. "spec" is the older word for an analytic and
    // it survived on this one line.
    expect(
      screen.getByText('This hunt ran one query from a written analytic. No model scored it.'),
    ).toBeInTheDocument();
  });

  it('hides the dial on a null confidence whoever started the hunt, not on the actor', async () => {
    // The dial reads the field, not the actor. A hunt an analyst started
    // whose report carries no confidence gets no dial and no invented 0.00;
    // the catalog's "no model call" sentence stays the catalog's, because
    // "ran one query from a written spec" would be false of this hunt.
    vi.mocked(getHunt).mockResolvedValue(
      catalogHunt({
        objective: 'hunt for beaconing to rare external IPs',
        kind: 'chat',
        narrative: 'Reviewed 4 documents; the pattern is consistent with a scanner.',
        startedBy: 'analyst',
        confidence: null,
      }),
    );
    mount();
    await screen.findByText(catalogFinding.title);
    expect(screen.queryByText('0.00')).toBeNull();
    expect(screen.queryByText(/^confidence$/i)).toBeNull();
    expect(screen.queryByText(/^no model call$/i)).toBeNull();
  });

  it('still shows the dial for a model hunt that genuinely scored 0.00', async () => {
    // The negative control for the detection rule. This hunt was run by an
    // analyst through the console, the model ran, and it landed on 0.00. That
    // zero is a MEASUREMENT and must keep its dial — a rule keyed on the
    // number being zero would swallow it.
    vi.mocked(getHunt).mockResolvedValue(
      catalogHunt({
        objective: 'hunt for beaconing to rare external IPs',
        kind: 'chat',
        narrative: 'Reviewed 4 documents; the pattern is consistent with a scanner.',
        startedBy: 'analyst',
        confidence: 0,
      }),
    );
    mount();
    await screen.findByText(catalogFinding.title);
    expect(screen.getByText('0.00')).toBeInTheDocument();
    expect(screen.getByText(/^confidence$/i)).toBeInTheDocument();
    expect(screen.queryByText(/^no model call$/i)).toBeNull();
  });

  it('still shows the dial for a scheduled model hunt, which is also kind=triggered', async () => {
    // The second negative control: `kind` cannot be the detection signal.
    // A catalog hunt is kind='triggered', but so is every scheduled hunt the
    // model runs, and those DO have a confidence worth showing.
    vi.mocked(getHunt).mockResolvedValue(
      catalogHunt({
        objective: 'nightly sweep for credential access',
        kind: 'triggered',
        narrative: 'Reviewed 4 documents; the pattern is consistent with a scanner.',
        startedBy: 'scheduler',
        confidence: 0.62,
      }),
    );
    mount();
    await screen.findByText(catalogFinding.title);
    expect(screen.getByText('0.62')).toBeInTheDocument();
    expect(screen.getByText(/^confidence$/i)).toBeInTheDocument();
  });
});

describe("HuntDetail — a catalog finding's authoring-time prose vs this run", () => {
  // findings.py composes a candidate's detail as "<the spec's own description>
  // Matched N documents for <kind> <key><span>". Rendered as one paragraph, the
  // author's measurements ("the range currently holds only 14 documents") read
  // as fresh measurement, and they quietly go false as the grid grows.
  it("shows this run's match on its own, without the author's numbers", async () => {
    mount();
    await screen.findByText(catalogFinding.title);
    const run = screen.getByText(/^Matched 4 documents for ip 192\.0\.2\.254/);
    expect(run.textContent).not.toMatch(/14 documents/);
    expect(run.textContent).not.toMatch(/OpenCanary honeypot recorded/);
  });

  it("labels the spec's prose as written when the detection was authored", async () => {
    mount();
    await screen.findByText(catalogFinding.title);
    expect(screen.getByText(/the author wrote this text before this run/i)).toBeInTheDocument();
    const rationale = screen.getByText(/^An OpenCanary honeypot recorded/);
    expect(rationale.textContent).toContain('the range currently holds only 14 documents');
    expect(rationale.textContent).not.toMatch(/Matched 4 documents/);
  });

  // The split keyed on the sentence a CANDIDATE finding ends with, so it never
  // fired on a visibility-gap finding — and on a quiet grid every catalog
  // finding is a visibility gap. It is also the case where the spec's prose
  // misleads most: this run saw nothing, so every number on screen was
  // measured by the author, once, on a grid that has moved since.
  it("sets the author's prose apart on a visibility-gap finding too", async () => {
    vi.mocked(getHunt).mockResolvedValue(
      catalogHunt({
        findings: [gapFinding],
        narrative:
          'Something connected to a decoy service: no telemetry. The spec\'s precondition ' +
          'matched nothing in the 90 days to 2026-09-05T12:00:00Z, so this is a coverage gap ' +
          'rather than a clean result.',
      }),
    );
    mount();
    await screen.findByText(gapFinding.title);
    expect(screen.getByText(/the author wrote this text before this run/i)).toBeInTheDocument();
    const run = screen.getByText(/^This spec found nothing, but it also could not see/);
    expect(run.textContent).not.toMatch(/14 documents/);
    const rationale = screen.getByText(/^An OpenCanary honeypot recorded/);
    expect(rationale.textContent).toContain('the range currently holds only 14 documents');
    expect(rationale.textContent).not.toMatch(/could not see/);
  });

  // Hunts recorded before the fields existed still carry the composed string
  // and nothing else. The tail match stays for them, and only for them.
  it('still splits a candidate finding recorded before the seam was carried', async () => {
    const legacy = { ...catalogFinding, specRationale: undefined, matchedDocs: undefined };
    vi.mocked(getHunt).mockResolvedValue(catalogHunt({ findings: [legacy] }));
    mount();
    await screen.findByText(legacy.title);
    const run = screen.getByText(/^Matched 4 documents for ip 192\.0\.2\.254/);
    expect(run.textContent).not.toMatch(/14 documents/);
    expect(screen.getByText(/^An OpenCanary honeypot recorded/)).toBeInTheDocument();
  });

  // A rationale that is not actually the head of the detail is a mismatch
  // between two fields of the same record, and cutting on it would drop text.
  it('renders the detail whole when the carried prose is not its opening', async () => {
    const mismatched = {
      ...catalogFinding,
      detail: 'A sentence the spec never wrote, with no seam in it at all.',
      specRationale: SPEC_PROSE,
      matchedDocs: undefined,
    };
    vi.mocked(getHunt).mockResolvedValue(catalogHunt({ findings: [mismatched] }));
    mount();
    await screen.findByText(mismatched.title);
    expect(screen.getByText(mismatched.detail)).toBeInTheDocument();
    expect(screen.queryByText(/the author wrote this text before this run/i)).toBeNull();
  });

  it("leaves a model hunt's detail alone even when it reads the same way", async () => {
    // The negative control for the split. The two halves are separable only by
    // matching the sentence findings.py appends, and nothing stops a model from
    // writing that same sentence itself. Splitting is therefore gated on the
    // hunt being a catalog hunt, so a model-authored detail is never carved up
    // on a guess about where its prose ends.
    vi.mocked(getHunt).mockResolvedValue(
      catalogHunt({
        startedBy: 'analyst',
        kind: 'chat',
        confidence: 0.7,
        narrative: 'Reviewed the decoy traffic.',
      }),
    );
    mount();
    await screen.findByText(catalogFinding.title);
    expect(screen.queryByText(/the author wrote this text before this run/i)).toBeNull();
    expect(screen.getByText(catalogFinding.detail)).toBeInTheDocument();
  });
});

describe('HuntDetail — a catalog finding’s citation chips', () => {
  it('opens the document behind each cited id', async () => {
    vi.mocked(getEvent).mockResolvedValue({
      id: CITATIONS[0],
      dataset: 'opencanary',
      timestamp: '2026-09-04T17:58:42.105Z',
      source: { source: { ip: '192.0.2.254' } },
    });
    mount();
    await screen.findByText(catalogFinding.title);
    // The entity chip pivots to the entity page: on the finding card and again
    // in the Affected hosts rail. Both are real links.
    expect(screen.getAllByRole('link', { name: '192.0.2.254' })).toHaveLength(2);
    // The document ids beside it were dashed chips that did nothing, because
    // the app had no document viewer to send them to. A citation is the proof
    // the finding is real, so each one opens its document.
    for (const c of CITATIONS) expect(screen.getByRole('button', { name: c })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: CITATIONS[0] }));
    await waitFor(() => expect(getEvent).toHaveBeenCalledWith(CITATIONS[0]));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('source.ip')).toBeTruthy();
  });

  it('says how many of the matching documents these ids are', async () => {
    mount();
    await screen.findByText(catalogFinding.title);
    // The narrative says 4 matching documents and three ids are shown, with
    // nothing accounting for the fourth. execute.py's MAX_SAMPLE_IDS = 3 caps
    // top_hits per bucket, so these are a sample and the page should say so.
    expect(screen.getByText(/3 of 4 matching documents/i)).toBeInTheDocument();
  });

  it('claims nothing about a total it cannot read', async () => {
    // The count comes out of the same composed sentence the detail split reads.
    // A model hunt's citations are not a capped sample of anything, so no
    // sample-versus-total line is invented for them.
    vi.mocked(getHunt).mockResolvedValue(
      catalogHunt({
        startedBy: 'analyst',
        kind: 'chat',
        confidence: 0.7,
        narrative: 'Reviewed the decoy traffic.',
      }),
    );
    mount();
    await screen.findByText(catalogFinding.title);
    expect(screen.queryByText(/of 4 matching documents/i)).toBeNull();
  });
});

describe('HuntDetail — the timeline of a hunt that has no steps by construction', () => {
  it('does not promise steps that will never arrive', async () => {
    mount();
    await screen.findByText(catalogFinding.title);
    // "HUNT TIMELINE 0 steps · 0s — No steps yet." on a hunt marked Complete.
    // "Yet" promises a second act. A catalog hunt is one query; there is none.
    expect(screen.queryByText('No steps yet.')).toBeNull();
    expect(screen.queryByText(/0 steps/)).toBeNull();
    expect(screen.getByText(/single Elasticsearch query/i)).toBeInTheDocument();
  });

  it('still says "yet" for a model hunt whose steps have not landed', async () => {
    // The negative control. A model hunt with an empty timeline genuinely may
    // get steps, so "yet" is the right word there and must survive this change.
    vi.mocked(getHunt).mockResolvedValue(
      catalogHunt({
        startedBy: 'analyst',
        kind: 'chat',
        status: 'running',
        confidence: 0.7,
        narrative: 'Reviewed the decoy traffic.',
      }),
    );
    mount();
    await screen.findByText(catalogFinding.title);
    expect(screen.getByText('No steps yet.')).toBeInTheDocument();
    expect(screen.queryByText(/single Elasticsearch query/i)).toBeNull();
  });
});
