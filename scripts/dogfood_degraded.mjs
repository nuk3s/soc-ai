// UI dogfood of soc-ai against a DEGRADED Security Onion grid.
//
// Walks every screen — and every action worth clicking — through five grid
// states, screenshotting each one, so a human can answer the only question that
// matters: does a tired analyst at 3am understand that what they are looking at
// is INCOMPLETE, and do they know what to do next?
//
// The failure being hunted is a FALSE ALL-CLEAR: an outage rendered as a quiet
// network. A loud error is strictly better than a quiet lie.
//
// Drive it with scripts/dogfood_degraded.sh, which seeds a throwaway store,
// starts mock_es.py --degraded-control and the real app cwd'd outside the repo.
// Standalone:
//   BASE=http://127.0.0.1:8907 MOCK=http://127.0.0.1:19207 \
//   MANIFEST=/tmp/degraded-dogfood/manifest.json \
//   node scripts/dogfood_degraded.mjs
//
// Env:
//   BASE      the app             (default http://127.0.0.1:8907)
//   MOCK      mock_es control     (default http://127.0.0.1:19207)
//   MANIFEST  seed_demo manifest  (default /tmp/degraded-dogfood/manifest.json)
//   OUT       shot root           (default /tmp/degraded-dogfood)
//   STATES    comma list          (default healthy,down,half-read,saturated,stalled)
//   SCREENS   comma list of screen names, to re-shoot a subset
//   NO_ACTIONS=1    reads only — much faster, for a first smoke
//   DEBUG_SETTLE=1  trace the in-flight count while waiting for a screen
//
// Output, per state:
//   <OUT>/<state>/<screen>.png                        the screen as it settled,
//                                                     at 1440x900 — fold included
//   <OUT>/<state>/<screen>-full.png                   the same screen at full
//                                                     content height, written
//                                                     ONLY when it overflows
//   <OUT>/<state>/<screen>-after-<action>.png         the click's immediate result
//   <OUT>/<state>/<screen>-after-<action>-later.png   the same screen once a
//                                                     background job has landed
//   <OUT>/<state>/network.json                        per capture: XHR statuses,
//                                                     calls still open at the end,
//                                                     console errors, wall-clock ms
//
// Read network.json alongside the images. A screen that looks fine while its
// API 500s is one finding; a screen that looks broken while every call returns
// 200 is a different one; and in the `stalled` state the DURATION is the
// finding, so it is recorded for every capture.
//
// States run in one process against ONE app, by design — that is what makes a
// per-state comparison meaningful. The cost is that writes accumulate across
// states in run order, so when a pristine baseline matters, run one state per
// invocation: the orchestrator reseeds the store every time.
//
// NEVER point this at a deployed instance. BASE and MOCK are 127.0.0.1 by
// construction and every byte of data is synthetic.
import pw from '../frontend/node_modules/playwright/index.js';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

const { chromium } = pw;

const BASE = process.env.BASE || 'http://127.0.0.1:8907';
const MOCK = process.env.MOCK || 'http://127.0.0.1:19207';
const OUT = process.env.OUT || '/tmp/degraded-dogfood';
const MANIFEST = process.env.MANIFEST || `${OUT}/manifest.json`;
const ALL_STATES = ['healthy', 'down', 'half-read', 'saturated', 'stalled'];
const STATES = (process.env.STATES || ALL_STATES.join(',')).split(',').map((s) => s.trim()).filter(Boolean);
const ONLY_SCREENS = (process.env.SCREENS || '').split(',').map((s) => s.trim()).filter(Boolean);
const NO_ACTIONS = process.env.NO_ACTIONS === '1';

// A page is "settled" once no API call has been in flight for QUIET_MS. The
// floor exists because a fresh navigation is briefly quiet BEFORE the SPA's
// first fetch leaves — settling there would screenshot an empty shell and call
// it a clean render.
const QUIET_MS = 900;
const SETTLE_FLOOR_MS = 1400;

// Caps, not expectations: a capture that hits its cap is itself the finding, so
// every cap is recorded next to the elapsed time. `stalled` gets a long one
// because the point is to measure how long an unguarded route hangs (the ES
// client's own budget is request_timeout 30s x (1 + 2 retries) = ~90s).
const CAP = (state) => (state === 'stalled' ? 105_000 : 30_000);

// The analyst's screen. Kept as the primary shot for every capture so the FOLD
// stays visible: "the honest degraded banner is 1,400px below the fold" is
// itself a finding, and a full-height shot alone would destroy it.
const VIEWPORT = { width: 1440, height: 900 };
// Ceiling on the companion full-height shot. A screen longer than this is
// recorded as `truncated: true` rather than silently cropped.
const MAX_FULL_H = 8000;

const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));
const log = (...a) => console.log(...a);
const slug = (s) => s.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '').toLowerCase();

// ---------------------------------------------------------------------------
// mock_es control
// ---------------------------------------------------------------------------

const setGridState = async (state) => {
  const res = await fetch(`${MOCK}/__degrade/${state}`, { method: 'POST' });
  const body = await res.json();
  if (!res.ok || body.state !== state) {
    throw new Error(`could not switch the mock grid to ${state}: ${JSON.stringify(body)}`);
  }
  return body;
};

// ---------------------------------------------------------------------------
// Recorder — XHR statuses, console errors and wall clock, per capture
// ---------------------------------------------------------------------------

const isApi = (url) => url.includes('/api/v1/') || url.endsWith('/healthz');
const short = (url) => {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return url;
  }
};

function makeRecorder(page) {
  const rec = { on: false, inflight: 0, calls: [], errors: [], started: new Map() };

  const track = (req) => {
    const t = req.resourceType();
    return (t === 'xhr' || t === 'fetch') && isApi(req.url());
  };

  page.on('request', (req) => {
    if (!track(req)) return;
    rec.inflight += 1;
    rec.started.set(req, Date.now());
  });
  const finish = (req, status, note) => {
    if (!track(req)) return;
    rec.inflight = Math.max(0, rec.inflight - 1);
    const t0 = rec.started.get(req);
    rec.started.delete(req);
    if (!rec.on) return;
    rec.calls.push({
      method: req.method(),
      path: short(req.url()),
      status,
      ms: t0 ? Date.now() - t0 : null,
      ...(note ? { note } : {}),
    });
  };
  page.on('requestfinished', async (req) => {
    let status = null;
    try {
      status = (await req.response())?.status() ?? null;
    } catch {
      /* response gone — recorded as null */
    }
    finish(req, status);
  });
  page.on('requestfailed', (req) => finish(req, null, req.failure()?.errorText || 'request failed'));
  page.on('console', (m) => {
    if (rec.on && m.type() === 'error') rec.errors.push(m.text().slice(0, 300));
  });
  page.on('pageerror', (e) => {
    if (rec.on) rec.errors.push(`PAGEERROR ${String(e).slice(0, 300)}`);
  });

  rec.start = () => {
    rec.on = true;
    rec.calls = [];
    rec.errors = [];
    // Zero the in-flight counter, not just the log. A request torn down by a
    // navigation never emits `requestfinished` OR `requestfailed`, so the
    // counter leaks by one per abandoned XHR and "quiet" becomes unreachable —
    // which silently turns every capture into a cap-length hang and makes the
    // whole run look like the app is stalling. Each capture counts only the
    // calls it fired.
    rec.inflight = 0;
    rec.started.clear();
  };
  /** Forget requests that were already open at `ts`.
   *
   *  Called once a navigation has been issued: the OUTGOING screen's polls are
   *  torn down by the browser without emitting `requestfinished` or
   *  `requestfailed`, so each one would otherwise sit in the in-flight count
   *  forever and make the incoming screen look like it hung for the full cap.
   *  That is the difference between "the dashboard was still polling when I
   *  clicked away" and "Alerts hung for 30 seconds" — and reporting the second
   *  when the first happened would fabricate exactly the kind of finding this
   *  run exists to detect. */
  rec.dropOpenBefore = (ts) => {
    for (const [req, t0] of rec.started) {
      if (t0 <= ts) {
        rec.started.delete(req);
        rec.inflight = Math.max(0, rec.inflight - 1);
      }
    }
  };
  rec.stop = () => {
    rec.on = false;
    // Requests still open when the capture ends. On a stalled grid this is the
    // whole finding — "the screen hung" is not actionable, "GET /api/v1/alerts
    // never came back" is — and it is also the only way to tell a hang apart
    // from a page that simply polls forever.
    const pending = [...rec.started.entries()].map(([req, t0]) => ({
      method: req.method(),
      path: short(req.url()),
      open_ms: Date.now() - t0,
    }));
    return {
      xhr: rec.calls,
      ...(pending.length ? { in_flight_at_end: pending } : {}),
      console_errors: [...new Set(rec.errors)],
    };
  };
  return rec;
}

/** Wait until no API call has been in flight for QUIET_MS, or the cap expires.
 *  Returns whether it settled on its own — a false here means the screen was
 *  still fetching when we gave up, which for `stalled` IS the finding. */
async function settle(page, rec, capMs) {
  const t0 = Date.now();
  let quietSince = Date.now();
  for (;;) {
    const elapsed = Date.now() - t0;
    if (elapsed >= capMs) return false;
    if (rec.inflight > 0) quietSince = Date.now();
    else if (Date.now() - quietSince >= QUIET_MS && elapsed >= SETTLE_FLOOR_MS) return true;
    if (process.env.DEBUG_SETTLE) log(`      settle t=${elapsed} inflight=${rec.inflight} quiet=${Date.now() - quietSince}`);
    await page.waitForTimeout(120);
  }
}

// ---------------------------------------------------------------------------
// Capture primitives
// ---------------------------------------------------------------------------

/** How far the content runs past the bottom of the screen, in px.
 *
 *  Playwright's `fullPage: true` is a NO-OP in this app and that is a trap: the
 *  AppShell is `h-screen overflow-hidden` with an inner `flex-1 overflow-y-auto`
 *  pane, so the DOCUMENT never scrolls and every "full page" shot comes back
 *  exactly one viewport tall. Long screens (Config, an investigation report, a
 *  hunt) are cropped at the fold with nothing in the image saying so — and a
 *  reader scoring these shots would read the missing half as "nothing wrong down
 *  there", which is the same false all-clear this run exists to hunt.
 *
 *  Every candidate pane is a flex child of the same `h-screen` column, so its
 *  clientHeight tracks the viewport 1:1 — growing the viewport by the largest
 *  overflow fits whichever pane is worst. Drawers are included on purpose: the
 *  `investigate` action opens one, and it scrolls independently of the shell. */
const contentOverflowPx = (page) =>
  page
    .evaluate(() => {
      const panes = [...document.querySelectorAll('div.flex-1.overflow-y-auto')].filter(
        (el) => el.clientHeight > 200,
      );
      return panes.reduce((max, el) => Math.max(max, el.scrollHeight - el.clientHeight), 0);
    })
    .catch(() => 0);

function makeCapturer(page, rec, state, dir, entries) {
  const capMs = CAP(state);

  /** Companion shot of everything below the fold, or null when it all fits. */
  const shootFull = async (file) => {
    const overflow = await contentOverflowPx(page);
    if (overflow < 24) return null; // fits on the screen; the primary shot is whole
    const wanted = VIEWPORT.height + overflow;
    const height = Math.min(MAX_FULL_H, wanted);
    try {
      await page.setViewportSize({ width: VIEWPORT.width, height });
      await page.waitForTimeout(400); // relayout + any height-dependent render
      await page.screenshot({ path: `${dir}/${file}-full.png`, fullPage: true });
      return { full_file: `${file}-full.png`, below_fold_px: overflow, full_h: height, truncated: wanted > MAX_FULL_H };
    } catch (e) {
      return { full_error: String(e).slice(0, 160) };
    } finally {
      // Always restore, even if the shot threw: every later capture's timings
      // and layout depend on the analyst-sized screen.
      await page.setViewportSize(VIEWPORT).catch(() => {});
      await page.waitForTimeout(200);
    }
  };

  const finishCapture = async (file, meta) => {
    const settled = await settle(page, rec, capMs);
    // Stop the clock BEFORE the cosmetic pause: `ms` is the number the stalled
    // state is read on, so it must be time the analyst actually waits, not
    // time this script spends being polite to a fade-in.
    const ms = Date.now() - meta.t0;
    await page.waitForTimeout(500); // count-ups / fade-ins
    // The screen as the analyst first meets it, fold and all.
    await page.screenshot({ path: `${dir}/${file}.png` }).catch((e) => {
      entries.push({ ...meta, file, error: `screenshot failed: ${String(e).slice(0, 160)}` });
    });
    const full = await shootFull(file);
    entries.push({
      ...meta,
      t0: undefined,
      file: `${file}.png`,
      ms,
      settled,
      cap_ms: capMs,
      ...(full || {}),
      ...rec.stop(),
    });
    log(
      `    ${file}.png  ${ms}ms${settled ? '' : ' [HIT THE CAP — still fetching]'}` +
        (full?.below_fold_px ? `  (+${full.below_fold_px}px below the fold → ${file}-full.png)` : ''),
    );
  };

  const navigate = async (path, onError) => {
    // A same-pathname goto that only changes the hash is a same-document
    // navigation — the SPA would keep its already-loaded (possibly healthy)
    // data and the shot would be of the previous state. Bounce through blank.
    try {
      if (new URL(page.url()).pathname === new URL(BASE + path).pathname) {
        await page.goto('about:blank');
      }
    } catch {
      /* first navigation: page.url() is about:blank */
    }
    const issuedAt = Date.now();
    await page.goto(`${BASE}${path}`, { waitUntil: 'domcontentloaded', timeout: capMs }).catch(onError);
    rec.dropOpenBefore(issuedAt);
    await page.waitForLoadState('load', { timeout: 10_000 }).catch(() => {});
  };

  return {
    /** Load a screen fresh and shoot it once it stops fetching. */
    async screen(name, path) {
      rec.start();
      const meta = { screen: name, action: null, url: path, t0: Date.now() };
      await navigate(path, (e) => entries.push({ screen: name, nav_error: String(e).slice(0, 200) }));
      await finishCapture(name, meta);
    },

    /** Click something, then shoot the RESULT once it settles.
     *
     *  Every action reloads its screen first. Without that, one action's click
     *  poisons the next: clicking Investigate on Alerts opens a drawer, and the
     *  three actions after it then "fail to find" their controls because they
     *  are running against the drawer. Reloading also keeps the recorded XHRs
     *  to the ones the CLICK fired — the reload's own traffic lands before
     *  rec.start() and stays out of the record.
     *
     *  `fn` returning false (or throwing) is recorded as an explicit skip, never
     *  as a silent pass: a control that is absent in a degraded state is a fact
     *  about the product and belongs in the report. */
    async action(screenName, screenPath, actionName, fn, opts = {}) {
      if (NO_ACTIONS) return;
      await navigate(screenPath, () => {});
      await settle(page, rec, capMs); // act on a screen that has its data
      rec.start();
      const meta = { screen: screenName, action: actionName, url: screenPath, t0: Date.now() };
      let ran = true;
      let why = null;
      try {
        ran = (await fn()) !== false;
      } catch (e) {
        ran = false;
        why = String(e).slice(0, 200).replace(/\s+/g, ' ');
      }
      if (!ran) {
        rec.stop();
        entries.push({ screen: screenName, action: actionName, skipped: why || 'control not present' });
        log(`    - skipped ${screenName}/${actionName}: ${why || 'control not present'}`);
        return;
      }
      await finishCapture(`${screenName}-after-${slug(actionName)}`, meta);

      // Background jobs — the network sweep, a hunt, a backtest, auto-triage,
      // an identifier scan — return a 202-ish "started" the instant they are
      // queued. The shot above therefore catches a spinner, not an outcome, and
      // the whole point of walking the actions is the OUTCOME: the degraded
      // badge, the partial-coverage note, the honest failure card. So opted-in
      // actions get a second capture after the job has had time to land.
      if (opts.later) {
        await page.waitForTimeout(opts.later);
        rec.start();
        const meta2 = { screen: screenName, action: `${actionName} (after ${opts.later / 1000}s)`, url: screenPath, t0: Date.now() };
        await navigate(screenPath, () => {});
        await finishCapture(`${screenName}-after-${slug(actionName)}-later`, meta2);
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Small click helpers. Every one is best-effort by design: a control that is
// absent in a degraded state is a fact about the product, so it must be
// reported as a skip rather than crash the run.
// ---------------------------------------------------------------------------

/** Click the first match once it is actually visible, or report a skip.
 *
 *  The wait is bounded and deliberate: in a degraded state a control may render
 *  LATE or not at all, and "the button never appeared in 8 seconds" is a finding
 *  worth recording — not a reason to hang the run. */
const clickIfPresent = async (page, locator, { timeout = 8000 } = {}) => {
  const el = locator.first();
  try {
    await el.waitFor({ state: 'visible', timeout });
  } catch {
    return false;
  }
  await el.click({ timeout: 6000 });
  return true;
};

/** Tick one alert group's checkbox, then hit the bulk button that appears.
 *  Group ack and escalate are the two writes MR !70's sibling finding (G10)
 *  said 500 before acking anything, so both are worth a real click. The row
 *  checkboxes are `button[role=checkbox]` labelled "Select <rule name>"; the
 *  "Select all detections" one is excluded so the shot shows a single group. */
const selectFirstGroupThen = async (page, buttonName) => {
  const box = page.locator(
    'button[role="checkbox"][aria-label^="Select "]:not([aria-label="Select all detections"])',
  );
  if (!(await clickIfPresent(page, box))) return false;
  await page.waitForTimeout(400); // the selection strip animates in
  return clickIfPresent(page, page.getByRole('button', { name: buttonName }));
};

/** Open the raw-exception disclosure on every failed-load card on the screen.
 *
 *  Not cosmetic. The failed-load card renders IDENTICALLY in all four degraded
 *  states — "Couldn't load this view" over a collapsed `Details` — so without
 *  this the shots for `down`, `half-read`, `saturated` and `stalled` are the
 *  same picture, and the one thing that could tell a refused connection apart
 *  from a tripped circuit breaker (the exception text, ErrorState's `error
 *  .message`) never appears in the capture at all. That is how a reader ends up
 *  asserting the card explains nothing, or that it explains plenty — neither
 *  checkable from the pixels. Returns false on a healthy screen, where there is
 *  no card to open, and that skip is the honest record. */
const expandErrorDetails = async (page) => {
  const summaries = page.locator('details summary');
  const n = await summaries.count();
  if (!n) return false;
  for (let i = 0; i < n; i += 1) {
    await summaries
      .nth(i)
      .click({ timeout: 3000 })
      .catch(() => {});
  }
  return true;
};

/** Escalate the focused group with the `e` shortcut.
 *
 *  Not a stylistic choice: escalate has NO button on the Alerts console. The
 *  selection strip offers Acknowledge and Assign to me only, so the keyboard is
 *  the sole way an analyst reaches the escalate-group write — which is one of
 *  the two writes finding G10 said 500 before acking anything. `j` focuses the
 *  first row (it gains a ring-accent outline), and that outline is asserted
 *  before `e` is sent, so a shortcut that silently did not register is reported
 *  as a skip instead of screenshotting an unchanged page as a success. */
const escalateFocusedGroup = async (page) => {
  await page.keyboard.press('j');
  try {
    // Scoped to the ROW, not to any ring-accent on the page: other controls
    // carry that focus ring too, and a looser selector reported a successful
    // escalate on an alerts list that had failed to load a single row —
    // a screenshot of an unchanged error card, filed as an action that worked.
    await page
      .locator('div[class*="cursor-pointer"][class*="ring-accent"]')
      .first()
      .waitFor({ state: 'visible', timeout: 5000 });
  } catch {
    return false; // no row took keyboard focus — nothing to escalate
  }
  await page.keyboard.press('e');
  return true;
};

// ---------------------------------------------------------------------------
// The walkthrough
// ---------------------------------------------------------------------------

/** Marks an action that kicks off a BACKGROUND job: capture it twice, the
 *  second time once the job has had a chance to land. 12s is chosen against the
 *  console grid budget (webui_grid_timeout_s, 12) — long enough for a job whose
 *  grid reads time out to give up and write its real outcome. */
const JOB = { later: 12_000 };

/** Screens + the actions worth clicking on each. `ctx` carries ids discovered
 *  once, in the healthy state, so a degraded run never has to find a link on a
 *  page that may legitimately be showing an error card instead. */
const plan = (ctx) => [
  {
    name: 'dashboard',
    path: '/app/dashboard',
    actions: [
      [
        'ask-chat',
        async (page) => {
          const box = page.locator('textarea').first();
          if (!(await box.count())) return false;
          await box.fill('Which internal hosts talked to the internet in the last 24 hours?');
          await box.press('Enter');
          return true;
        },
      ],
      ['expand-error-details', expandErrorDetails],
    ],
  },
  {
    name: 'alerts',
    path: '/app/alerts',
    actions: [
      ['expand-error-details', expandErrorDetails],
      ['expand-group', (page) => clickIfPresent(page, page.locator('[class*="cursor-pointer"][class*="grid"]'))],
      ['investigate', (page) => clickIfPresent(page, page.locator('[aria-label="Investigate"]'))],
      ['ack-group', (page) => selectFirstGroupThen(page, /^Acknowledge/)],
      ['escalate-group', escalateFocusedGroup],
      // The Dashboard's Auto-Investigate tile is READ-ONLY — the sweep is
      // started here. Kicking it off from Alerts is what puts the degraded
      // badge on that tile, which the dashboard-after-run-sweep shot then reads.
      ['run-sweep', (page) => clickIfPresent(page, page.getByRole('button', { name: /Bulk Investigate/ })), JOB],
    ],
  },
  // Shot AFTER the sweep above, on purpose: this is the tile the sweep's
  // degraded badge lands on, and it is the single most important false-all-clear
  // surface in the product ("Last batch · 0 investigated" during an outage).
  { name: 'dashboard-after-run-sweep', path: '/app/dashboard', actions: [] },
  {
    name: 'investigations',
    path: '/app/investigations',
    actions: [
      [
        'bulk-rehunt',
        async (page) => {
          // The list's only checkbox is the toolbar's select-all; rows carry no
          // individual one, so this is how an analyst re-runs in bulk.
          if (!(await clickIfPresent(page, page.locator('[role="checkbox"], input[type="checkbox"]')))) return false;
          await page.waitForTimeout(400);
          return clickIfPresent(page, page.getByRole('button', { name: /Re-investigate/ }));
        },
        JOB,
      ],
    ],
  },
  {
    // The Emotet true positive: the richest report in the seed, and the one
    // whose evidence the analyst would be re-reading during an outage.
    name: 'investigation',
    path: `/app/investigation/${manifest.inv_emotet}`,
    actions: [['re-run', (page) => clickIfPresent(page, page.getByRole('button', { name: /Re-run investigation/ })), JOB]],
  },
  {
    // A SECOND investigation on purpose: "Request more info" only renders on a
    // needs-more-info verdict, so the true positive above can never exercise it.
    name: 'investigation-needs-info',
    path: `/app/investigation/${manifest.inv_dnstop}`,
    actions: [
      ['request-more-info', (page) => clickIfPresent(page, page.getByRole('button', { name: /Request more info/ })), JOB],
    ],
  },
  {
    name: 'hunts',
    path: '/app/hunts',
    actions: [
      [
        'start-template-hunt',
        async (page) => {
          // A template chip fills the objective; Start hunt submits it.
          await clickIfPresent(page, page.locator('button').filter({ hasText: /beacon|lateral|exfil|DNS|persistence|scan/i }));
          await page.waitForTimeout(500);
          return clickIfPresent(page, page.getByRole('button', { name: /^Start hunt/ }));
        },
        JOB,
      ],
    ],
  },
  { name: 'hunt-detail', path: `/app/hunts/${manifest.hunt}`, actions: [] },
  {
    name: 'hosts',
    path: '/app/hosts',
    actions: [
      [
        'rebuild-dossiers',
        (page) => clickIfPresent(page, page.getByRole('button', { name: /Rebuild now|Try the sweep again|Run the first sweep/ })),
        JOB,
      ],
    ],
  },
  ...(ctx.hostIp
    ? [
        {
          name: 'host-detail',
          path: `/app/hosts/${encodeURIComponent(ctx.hostIp)}`,
          // "Refresh host" only renders for a host that HAS a dossier; with the
          // store empty the page offers the network sweep instead, which is the
          // same write. Accept either so the action is never silently lost.
          actions: [
            [
              'refresh-host',
              (page) =>
                clickIfPresent(page, page.getByRole('button', { name: /Refresh host|Sweep the network now|^Refresh$/ })),
              JOB,
            ],
          ],
        },
      ]
    : []),
  { name: 'notifications', path: '/app/notifications', actions: [] },
  {
    name: 'backtest',
    path: '/app/backtest',
    actions: [['run-backtest', (page) => clickIfPresent(page, page.getByRole('button', { name: /^Run backtest/ })), JOB]],
  },
  { name: 'runbooks', path: '/app/runbooks', actions: [] },
  { name: 'config', path: '/app/config', actions: [] },
  {
    name: 'config-identifiers',
    path: '/app/config#internal-identifiers',
    actions: [['scan-now', (page) => clickIfPresent(page, page.getByRole('button', { name: /^Scan now/ })), JOB]],
  },
  { name: 'config-detection-tuning', path: '/app/config#detection-tuning', actions: [] },
  { name: 'config-egress', path: '/app/config#egress-policy', actions: [] },
  {
    name: 'config-diagnostics',
    path: '/app/config#diagnostics',
    // "Test ES" is the grid connection test — the one control on Config whose
    // entire job is to tell the truth about the grid.
    actions: [['connection-test', (page) => clickIfPresent(page, page.getByRole('button', { name: /^Test ES$/ }))]],
  },
];

/** The audit chain verifier has a backend route but NO button anywhere in the
 *  SPA, so it cannot be screenshotted. Probe it over the logged-in session
 *  instead and record the status — an outage that reports the chain "intact" is
 *  a false all-clear even without a pixel to look at. */
async function probeApiOnlyRoutes(page, state, entries) {
  const probes = [['audit-verify-chain', 'GET', '/api/v1/config/audit/verify-chain?days=7']];
  for (const [name, method, path] of probes) {
    const t0 = Date.now();
    try {
      const res = await page.request.fetch(`${BASE}${path}`, { method, timeout: CAP(state) });
      const body = await res.text();
      entries.push({
        screen: name,
        action: null,
        api_only: 'no UI control exists for this route — probed over the session',
        ms: Date.now() - t0,
        xhr: [{ method, path, status: res.status(), ms: Date.now() - t0 }],
        body: body.slice(0, 600),
      });
      log(`    [api] ${name} → ${res.status()} in ${Date.now() - t0}ms`);
    } catch (e) {
      entries.push({
        screen: name,
        action: null,
        api_only: 'no UI control exists for this route — probed over the session',
        ms: Date.now() - t0,
        xhr: [{ method, path, status: null, ms: Date.now() - t0, note: String(e).slice(0, 200) }],
      });
      log(`    [api] ${name} → transport failure in ${Date.now() - t0}ms`);
    }
  }
}

const main = async () => {
  mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { ...VIEWPORT }, ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const rec = makeRecorder(page);

  // ---- log in against a HEALTHY grid ------------------------------------
  // Sessions live in SQLite, not in Elasticsearch, so the login survives every
  // grid state that follows — but signing in through an outage would only be a
  // test of the login page.
  await setGridState('healthy');
  await page.goto(`${BASE}/app/login`, { waitUntil: 'domcontentloaded', timeout: 30_000 });
  await page.fill('#username', manifest.admin_user);
  await page.fill('#password', manifest.admin_password);
  await page.click('button:has-text("Sign in")');
  await page.waitForURL(/\/app\/(dashboard|alerts)/, { timeout: 30_000 });
  log(`logged in as ${manifest.admin_user}`);

  // Pick the host-detail target once, healthy, so a degraded run never has to
  // find a link on a hosts LIST that may legitimately be showing an error card.
  //
  // The fallback matters: this harness's mock grid answers the alert queries and
  // not the host-census aggregations, so the dossier store stays empty and the
  // hosts list has nothing to click. The host PAGE is still worth walking —
  // /dossiers/{ip} and /dossiers/{ip}/activity both answer for an unknown IP,
  // and the activity lane is one of the surfaces the sweep added a degraded
  // badge to. 198.51.100.23 is RFC 5737 TEST-NET-2 and appears in the seeded
  // demo alerts, so the page has something real to say about it.
  const discovered = { hostIp: '198.51.100.23', hostIpSource: 'RFC 5737 fallback (dossier store empty)' };
  try {
    const res = await page.request.get(`${BASE}/api/v1/dossiers?limit=1`);
    const ip = (await res.json())?.rows?.[0]?.ip;
    if (ip) {
      discovered.hostIp = ip;
      discovered.hostIpSource = 'dossier store';
    }
  } catch {
    /* keep the fallback */
  }
  log(`host detail target: ${discovered.hostIp} (${discovered.hostIpSource})`);

  const screens = plan(discovered).filter((s) => !ONLY_SCREENS.length || ONLY_SCREENS.includes(s.name));

  for (const state of STATES) {
    const dir = `${OUT}/${slug(state)}`;
    mkdirSync(dir, { recursive: true });
    const entries = [];
    log(`\n===== grid state: ${state} =====`);
    const flipped = await setGridState(state);
    const cap = makeCapturer(page, rec, state, dir, entries);
    const t0 = Date.now();

    for (const s of screens) {
      log(`  ${s.name}`);
      await cap.screen(s.name, s.path);
      for (const [actionName, fn, opts] of s.actions) {
        await cap.action(s.name, s.path, actionName, () => fn(page), opts);
      }
    }
    await probeApiOnlyRoutes(page, state, entries);

    writeFileSync(
      `${dir}/network.json`,
      JSON.stringify(
        {
          state,
          stall_seconds: flipped.stall_seconds,
          captured_at: new Date().toISOString(),
          wall_clock_ms: Date.now() - t0,
          settle_quiet_ms: QUIET_MS,
          cap_ms: CAP(state),
          note:
            'The LLM gateway is a mock that only answers /v1/models — every model call fails in ' +
            'EVERY state, healthy included. Treat the healthy run as the control: an error that ' +
            'appears in a degraded state but not in healthy is the grid talking.',
          captures: entries,
        },
        null,
        2,
      ),
    );
    log(`  wrote ${dir}/network.json (${entries.length} captures, ${Math.round((Date.now() - t0) / 1000)}s)`);
  }

  // Leave the mock healthy so a follow-up run does not start mid-outage.
  await setGridState('healthy');
  await browser.close();
  log(`\ndone — ${OUT}/<state>/`);
};

main().catch((e) => {
  console.error('DOGFOOD FAILED:', e);
  process.exit(1);
});
