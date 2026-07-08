// Playwright capture for the docs screenshots — runs against the LOCAL demo
// instance stood up by run_demo_capture.sh (synthetic TEST-NET data only).
//
// Captures at a 1440x900 viewport with deviceScaleFactor=2 so each PNG is
// 2880x1800 — the exact dimensions of the previous docs/img assets.
//
// Env: BASE (default http://127.0.0.1:8899), MANIFEST (manifest.json from
// seed_demo.py), OUT (shot dir, default /tmp/soc-ai-demo/shots).
import pw from '../../frontend/node_modules/playwright/index.js';
import { mkdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const BASE = process.env.BASE || 'http://127.0.0.1:8901';
const OUT = process.env.OUT || '/tmp/soc-ai-demo/shots';
const MANIFEST = process.env.MANIFEST || '/tmp/soc-ai-demo/manifest.json';
const { chromium } = pw;

const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));
mkdirSync(OUT, { recursive: true });

const shot = async (page, name) => {
  await page.waitForTimeout(600); // let count-up / fade-in animations settle
  await page.screenshot({ path: `${OUT}/${name}.png` }); // viewport-sized
  console.log(`  captured ${name}.png`);
};

const main = async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,
  });
  const page = await ctx.newPage();
  await page.emulateMedia({ reducedMotion: 'reduce' });
  page.on('pageerror', (e) => console.log('PAGE ERROR:', String(e).slice(0, 200)));

  // ---- login ----
  await page.goto(`${BASE}/app/login`, { waitUntil: 'networkidle' });
  await page.fill('#username', manifest.admin_user);
  await page.fill('#password', manifest.admin_password);
  await page.click('button:has-text("Sign in")');
  await page.waitForURL(/\/app\/(dashboard|alerts)/, { timeout: 20000 });
  console.log('logged in');

  // ---- alerts (expand the Emotet group so per-event rows show) ----
  await page.goto(`${BASE}/app/alerts`, { waitUntil: 'networkidle' });
  await page.waitForSelector('text=Emotet', { timeout: 20000 });
  const emotetRow = page.locator('text=ET MALWARE Win32/Emotet CnC Activity (POST)').first();
  await emotetRow.click().catch(() => {});
  await page.waitForTimeout(1500); // events fetch + expand
  await shot(page, 'screenshot-alerts');

  // ---- investigations list ----
  await page.goto(`${BASE}/app/investigations`, { waitUntil: 'networkidle' });
  await page.waitForSelector('text=Emotet', { timeout: 20000 });
  await shot(page, 'screenshot-investigations');

  // ---- investigation detail (the Emotet true positive) ----
  await page.goto(`${BASE}/app/investigation/${manifest.inv_emotet}`, {
    waitUntil: 'networkidle',
  });
  // networkidle means the detail JSON is loaded; the exact verdict label can
  // vary, so wait for the timeline heading (always present) and fall back to a
  // settle delay rather than fail the whole run on a text mismatch.
  await page
    .waitForSelector('text=/investigation timeline|model reasoning|verdict/i', { timeout: 15000 })
    .catch(() => {});
  await page.waitForTimeout(1500); // timeline + graph render
  await shot(page, 'screenshot-investigation');

  // ---- dashboard ----
  await page.goto(`${BASE}/app/dashboard`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000); // KPI cards + recent lists
  await shot(page, 'screenshot-dashboard');

  // ---- hunt detail ----
  await page.goto(`${BASE}/app/hunts/${manifest.hunt}`, { waitUntil: 'networkidle' });
  await page.waitForSelector('text=/finding|narrative|objective/i', { timeout: 15000 }).catch(() => {});
  await page.waitForTimeout(1200);
  await shot(page, 'screenshot-hunt');

  await browser.close();
  console.log(`done — shots in ${OUT}`);
};

main().catch((e) => {
  console.error('CAPTURE FAILED:', e);
  process.exit(1);
});
