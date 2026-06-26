// ---------------------------------------------------------------------------
// record_browser_walkthrough.mjs
//
// Records a polished, PUBLIC-SAFE screencast of soc-ai's REAL web UI.
//
// HOW IT WORKS (mocked-API, real-UI):
//   - Playwright loads the *real* deployed SPA bundle from a running instance
//     ($SOCAI_BASE/app/login, self-signed cert accepted). The HTML,
//     JS and CSS are the genuine production UI — there is NO lab data in the
//     bundle itself.
//   - EVERY `**/api/v1/**` request (and `**/healthz`) is intercepted with
//     page.route() and answered from the PUBLIC-SAFE fixtures defined below.
//     Any un-mapped /api/v1 route falls through to a safe default (200 `{}` or
//     an empty list), so NO real backend is ever contacted and only the
//     example fixtures can render.
//
// The recorded flow:
//   1. Login (admin / demo)            → SPA navigates to /app/alerts
//   2. Alerts console                  → one public-safe Emotet detection group
//   3. "Hunt with AI"                  → investigation starts; drawer shows
//      "Investigating…" with a live elapsed timer for ~5-8s (running polls),
//      then flips to the completed verdict.
//   4. Verdict                         → true_positive, confidence 0.92,
//      rationale headline, cited summary, expandable timeline.
//   5. Human-approval gate             → click Approve → "✓ Executed".
//
// Output: a Playwright .webm video (converted to GIF by the surrounding
// pipeline). Re-runnable and self-contained.
//
// Usage:  PLAYWRIGHT_DIR=/path/to/node_modules/playwright SOCAI_BASE=https://host:8443 \
//           node docs/demo/record_browser_walkthrough.mjs
// ---------------------------------------------------------------------------

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

// Resolve Playwright from PLAYWRIGHT_DIR if set, otherwise the default module
// resolution (install with `npm i playwright`, or point PLAYWRIGHT_DIR at it).
const require = createRequire(import.meta.url);
const PW_DIR = process.env.PLAYWRIGHT_DIR || 'playwright';
const { chromium } = require(PW_DIR);

const __dirname = dirname(fileURLToPath(import.meta.url));
const BASE = process.env.SOCAI_BASE || 'https://localhost:8443';
const OUT_DIR = process.env.OUT_DIR || resolve(__dirname, '_recording');

// ── timing helpers ──────────────────────────────────────────────────────────
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── PUBLIC-SAFE FIXTURES ─────────────────────────────────────────────────────
// All values are RFC1918 internal IPs, a synthetic sensor hostname, and one
// real abuse.ch Feodo/Emotet tracker IP (162.243.103.246) which is published
// public threat-intel — safe to show. NO lab IPs / hostnames / data.

const INV_ID = 'INV-2026-0042';
const GROUP_ID = 'emotet-cnc-post';
const APPROVE_TOKEN = 'demo-approve-token-0001';

const ME = { username: 'admin', role: 'admin', status: '' };

const HEALTH = {
  es: { ok: true, detail: 'Elasticsearch reachable · logs-* indices' },
  llm: { ok: true, detail: 'analyst model online' },
  pcap: { ok: true, detail: 'PCAP retrieval ready' },
};

// AlertGroup[] — exactly the shape Alerts.tsx consumes (camelCase).
const ALERTS = [
  {
    id: GROUP_ID,
    name: 'ETPRO TROJAN Win32/Emotet CnC Activity (POST)',
    kind: 'suricata',
    sev: 'high',
    count: 3,
    verdict: 'untriaged',
    conf: null,
    latest: '2m ago',
    latestTs: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
    inherited: false,
    owner: '',
    events: [],
    ackedCount: 0,
    escalatedCount: 0,
  },
];

// Events shown when the row is expanded (lazy /alerts/events) — public-safe.
const ALERT_EVENTS = [
  {
    id: 'evt-1',
    src: '10.0.0.42',
    dst: '162.243.103.246',
    host: 'so-sensor-1',
    proto: 'tcp',
    sev: 'high',
    port: 443,
    ts: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
    ago: '2m ago',
    investigated: false,
  },
];

// The most-representative-event picker the Hunt button calls first.
const REPRESENTATIVE = {
  alert_id: 'evt-1',
  src_ip: '10.0.0.42',
  dst_ip: '162.243.103.246',
  dst_port: 443,
  matched: 3,
  total: 3,
  reason: 'all 3 events share the same 10.0.0.42 → 162.243.103.246:443 flow',
};

// Shared investigation scaffold (host/ip/alert/meta/nodes/edges).
const INV_COMMON = {
  id: INV_ID,
  groupId: GROUP_ID,
  name: 'ETPRO TROJAN Win32/Emotet CnC Activity (POST)',
  kind: 'suricata',
  host: 'so-sensor-1',
  ip: '10.0.0.42',
  sev: 'high',
  nodes: [
    { id: 'n1', x: 18, y: 50, kind: 'compromised', label: '10.0.0.42' },
    { id: 'n2', x: 78, y: 50, kind: 'c2', label: '162.243.103.246' },
  ],
  edges: [{ from: 'n1', to: 'n2', kind: 'beacon', label: 'HTTP POST · Emotet C2' }],
  seedChat: [],
};

// Timeline steps shared by both the running and complete payloads — but the
// running payload exposes only the first couple so the drawer streams them in.
const TIMELINE_FULL = [
  {
    id: 's1',
    group: 'Prefetch & pivots',
    title: 'Pulled the alert and its Zeek conn record',
    time: '00:01',
    detail:
      'alert: ETPRO TROJAN Win32/Emotet CnC Activity (POST)\n'
      + 'src 10.0.0.42 → dst 162.243.103.246:443  (3 events, last 2m ago)\n'
      + 'zeek.conn: 3 outbound flows, 1 240 bytes up / 380 bytes down, duration 0.6s each',
  },
  {
    id: 's2',
    group: 'Tool calls',
    title: 'enrich_ip(162.243.103.246) → abuse.ch Feodo: LISTED',
    time: '00:03',
    detail:
      'enrich_ip(162.243.103.246)\n'
      + '  abuse.ch Feodo Tracker: LISTED (malware=Emotet, first_seen 2026-06-19)\n'
      + '  ASN: AS14061 DigitalOcean, LLC\n'
      + '  reverse DNS: none',
  },
  {
    id: 's3',
    group: 'Tool calls',
    title: 'query_zeek(http) → repeating POST beacon to /modules',
    time: '00:05',
    detail:
      'query_zeek(http, host=10.0.0.42)\n'
      + '  POST http://162.243.103.246/modules  (x3, ~60s apart)\n'
      + '  user-agent: Mozilla/5.0 (compatible; MSIE 9.0)\n'
      + '  request body: 1 240 B form-encoded — consistent with Emotet check-in',
  },
  {
    id: 's4',
    group: 'Decision',
    title: 'Concluded true_positive — confirmed Emotet C2 check-in',
    time: '00:06',
    detail:
      'Internal host beaconing to a tracked Emotet controller with the canonical\n'
      + 'POST check-in pattern. abuse.ch listing + matching Zeek HTTP behaviour are\n'
      + 'mutually corroborating. Verdict: true_positive (0.92).',
  },
];

// summary as structured SummarySegment[] so [1]/[2] render as citations.
const SUMMARY = [
  { t: 'text', v: 'Internal host ' },
  { t: 'mono', v: '10.0.0.42', tone: 'green' },
  { t: 'text', v: ' issued three HTTP POST check-ins to ' },
  { t: 'mono', v: '162.243.103.246', tone: 'amber' },
  { t: 'text', v: ', which abuse.ch Feodo Tracker lists as an active Emotet controller' },
  { t: 'cite', n: 2 },
  { t: 'text', v: '. The Zeek HTTP records show the canonical Emotet POST beacon to /modules on a ~60s interval' },
  { t: 'cite', n: 3 },
  { t: 'text', v: '. Both signals corroborate a live infection — not a false positive.' },
];

const RECOMMENDED_ACTIONS = [
  {
    id: 'a1',
    title: 'Escalate to a case and acknowledge the detection group',
    tag: 'escalate',
    rationale:
      'Confirmed Emotet C2. Escalate 10.0.0.42 for containment and acknowledge the '
      + 'remaining events so the queue reflects the triaged state.',
    // A live approval-gate token → the card renders an "Approve" button (no
    // confirm dialog) and flips straight to "✓ Executed" on approve.
    token: APPROVE_TOKEN,
  },
];

const ALERT_META = {
  id: 'evt-1',
  rule: 'ETPRO TROJAN Win32/Emotet CnC Activity (POST)',
  sid: '2849912',
  classtype: 'trojan-activity',
  category: 'A Network Trojan was detected',
  src: '10.0.0.42',
  dst: '162.243.103.246',
  proto: 'TCP',
  action: 'allowed',
  firstSeen: '4m ago',
  lastSeen: '2m ago',
  count: 3,
};

const INV_META = {
  model: 'analyst model',
  oracle: '—',
  ranBy: 'admin',
  ranAt: 'just now',
  toolCalls: 2,
  pivots: 1,
};

// status:'investigating' — drawer shows "Investigating…", elapsed timer,
// streaming steps. Only the first 2 steps are present so it looks live.
const INV_RUNNING = {
  ...INV_COMMON,
  verdict: 'untriaged',
  conf: 0,
  rationale: '',
  summary: [],
  status: 'investigating',
  elapsedLabel: 'running',
  elapsedSec: 2,
  actions: [],
  timeline: TIMELINE_FULL.slice(0, 2),
  alert: ALERT_META,
  meta: { ...INV_META, toolCalls: 1 },
  hostContext: [],
  oracle: null,
};

// status:'complete' — the full verdict.
const INV_COMPLETE = {
  ...INV_COMMON,
  verdict: 'true_positive',
  conf: 0.92,
  rationale:
    'Confirmed Emotet C2: internal host 10.0.0.42 is POSTing to 162.243.103.246, '
    + 'a tracked Feodo/Emotet controller — this is a real infection, not a false positive.',
  summary: SUMMARY,
  status: 'complete',
  elapsedLabel: '6s',
  elapsedSec: 6,
  actions: RECOMMENDED_ACTIONS,
  timeline: TIMELINE_FULL,
  alert: ALERT_META,
  meta: INV_META,
  hostContext: [
    { time: '00:05', label: 'Repeating POST beacon to Emotet C2', tone: 'high', w: 88, sev: 'HIGH' },
    { time: '00:03', label: 'Destination listed on abuse.ch Feodo Tracker', tone: 'high', w: 80, sev: 'HIGH' },
  ],
  oracle: null,
};

// ── route handler ────────────────────────────────────────────────────────────
// pollCount drives the running→complete transition: the first few polls of
// GET /investigations/{id} return "investigating", then it flips to "complete".
let pollCount = 0;
const RUNNING_POLLS = 3; // ~3 polls × 2.5s ≈ 7.5s of "Investigating…"

function json(route, body, status = 200) {
  return route.fulfill({
    status,
    contentType: 'application/json',
    headers: { 'Access-Control-Allow-Origin': '*' },
    body: JSON.stringify(body),
  });
}

async function handleApi(route) {
  const req = route.request();
  const url = new URL(req.url());
  const path = url.pathname.replace(/^.*\/api\/v1/, ''); // strip prefix
  const method = req.method();

  // healthz (non /api/v1) handled by a separate route; here is /api/v1/*
  if (path === '/login' && method === 'POST') {
    return json(route, { ok: true, username: 'admin', role: 'admin' });
  }
  if (path === '/me') return json(route, ME);
  if (path === '/health') return json(route, HEALTH);
  if (path === '/notifications') return json(route, []);
  if (path === '/workspaces') return json(route, [{ name: 'Home lab', env: 'prod' }]);
  if (path === '/auto-triage') {
    return json(route, {
      active: false, total: 0, hunted: 0, skipped: 0, failed: 0,
      finished_at: null, severities: [], note: null, current: null, tool_calls: 0,
    });
  }

  if (path === '/alerts' && method === 'GET') return json(route, ALERTS);
  if (path === '/alerts/events') return json(route, ALERT_EVENTS);
  if (path === '/alerts/representative') return json(route, REPRESENTATIVE);

  // Start a hunt → return the investigation id, reset the poll counter.
  if (path === '/hunt' && method === 'POST') {
    pollCount = 0;
    return json(route, { investigation_id: INV_ID });
  }

  // Poll the investigation: running for the first RUNNING_POLLS, then complete.
  if (/^\/investigations\/[^/]+$/.test(path) && method === 'GET') {
    pollCount += 1;
    const body = pollCount <= RUNNING_POLLS ? INV_RUNNING : INV_COMPLETE;
    // bump the running elapsed so the timer visibly advances
    if (body === INV_RUNNING) body.elapsedSec = 2 + pollCount * 2;
    return json(route, body);
  }

  // chat thread (drawer mounts an empty thread)
  if (/\/chat$/.test(path)) return json(route, { messages: [], pending: false });

  // Approve the action → ok. (token path → no confirm dialog)
  if (path === '/approve' && method === 'POST') return json(route, { ok: true });

  // Advisory execute path (in case a tokenless action is used)
  if (/\/actions\/\d+\/execute$/.test(path) && method === 'POST') {
    return json(route, {
      status: 'executed',
      title: 'Escalate to a case',
      detail: 'Case opened and 3 events acknowledged in Security Onion.',
      error: null,
    });
  }

  // ── safe default: empty object/list so nothing ever hits a real backend ──
  // Arrays for list-y endpoints, {} otherwise.
  const listy = /(alerts|investigations|hunts|users|tokens|notifications|workspaces|identifiers|danger)/.test(path);
  return json(route, listy ? [] : {});
}

// ── main ─────────────────────────────────────────────────────────────────────
async function main() {
  const browser = await chromium.launch({
    args: ['--ignore-certificate-errors', '--disable-dev-shm-usage'],
  });
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 1280, height: 800 },
    deviceScaleFactor: 1,
    recordVideo: { dir: OUT_DIR, size: { width: 1280, height: 800 } },
  });
  const page = await context.newPage();

  // Auto-accept any confirm() dialog (defensive — the token path skips it).
  page.on('dialog', (d) => d.accept().catch(() => {}));

  // Intercept ALL API traffic with the public-safe fixtures.
  await page.route('**/api/v1/**', handleApi);
  await page.route('**/healthz', (r) => json(r, { ok: true }));

  // ── 1. LOGIN ────────────────────────────────────────────────────────────
  await page.goto(`${BASE}/app/login`, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#username', { timeout: 15000 });
  await sleep(1200);
  await page.fill('#username', 'admin');
  await sleep(350);
  await page.fill('#password', 'demo');
  await sleep(500);
  await page.click('button[type="submit"]');

  // ── 2. ALERTS CONSOLE ─────────────────────────────────────────────────────
  await page.waitForURL('**/app/alerts', { timeout: 15000 });
  await page.waitForSelector('div.grid.cursor-pointer', { timeout: 15000 });
  await sleep(2500); // dwell so the grid + Emotet row is readable

  // ── 3. START THE HUNT ─────────────────────────────────────────────────────
  const huntBtn = page.locator('button[aria-label="Hunt with AI"]').first();
  await huntBtn.scrollIntoViewIfNeeded();
  await sleep(400);
  await huntBtn.click();

  // Drawer opens; wait for the "Investigating…" running state.
  await page.waitForSelector('text=Investigating…', { timeout: 15000 });
  // Let the elapsed timer + streaming steps run a beat.
  await sleep(7000);

  // ── 4. VERDICT (drawer flips to complete) ─────────────────────────────────
  await page.waitForSelector('text=confidence', { timeout: 15000 });
  await sleep(800);
  // Expand the first timeline step so the evidence detail is visible.
  const firstStep = page.locator('#tl-s1');
  if (await firstStep.count()) {
    await firstStep.scrollIntoViewIfNeeded();
    await sleep(400);
    await firstStep.click();
    await sleep(1800);
    await firstStep.click(); // collapse again
  }
  // Scroll back up to dwell on the verdict hero.
  await page.evaluate(() => {
    const el = document.querySelector('[class*="overflow-y-auto"]');
    if (el) el.scrollTo({ top: 0, behavior: 'smooth' });
    const drawer = document.querySelector('.fixed [class*="overflow"]');
    if (drawer) drawer.scrollTop = 0;
  });
  await sleep(2800);

  // ── 5. HUMAN-APPROVAL GATE ────────────────────────────────────────────────
  const approve = page.locator('button:has-text("Approve")').first();
  await approve.scrollIntoViewIfNeeded();
  await sleep(1000);
  await approve.click();
  // Card flips to "✓ Executed".
  await page.waitForSelector('text=Executed', { timeout: 8000 }).catch(() => {});
  await sleep(2500);

  // ── done ──────────────────────────────────────────────────────────────────
  await context.close(); // flushes the .webm
  await browser.close();

  const video = await page.video();
  const videoPath = video ? await video.path() : null;
  console.log(JSON.stringify({ videoPath, outDir: OUT_DIR }));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
