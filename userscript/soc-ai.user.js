// ==UserScript==
// @name         soc-ai: Hunt with AI
// @namespace    https://github.com/nuk3s/soc-ai
// @version      0.8.2
// @description  Inject a "Hunt with AI" button into Security Onion alert/hunt pages and stream the soc-ai triage assistant's analysis into a side panel.
// @author       soc-ai contributors
// @match        https://*/*
// @grant        GM_xmlhttpRequest
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_registerMenuCommand
// @connect      *
// @run-at       document-start
// @noframes
// ==/UserScript==
// SO 3.0.0 uses hash-routing (https://host/#/alerts...). Tampermonkey
// strips the hash for @match, so we need to match the host root and
// then guard inside the script.

(function () {
  'use strict';

  console.info('[soc-ai] userscript loaded on', location.href);

  // ---------------------------------------------------------------------------
  // /api/events/ fetch interception (the alert _id source of truth)
  // ---------------------------------------------------------------------------
  // SO 3.0.0's Vue frontend never writes alert ES _ids into the DOM. They
  // arrive in /api/events/ responses as event.id and live only in JS state.
  // We patch fetch at @run-at document-start so we install BEFORE the SO
  // bundle loads, then capture every event.id keyed by row-visible fields
  // (timestamp + rule.uuid + 5-tuple). On row click we resolve from this
  // cache.
  const _idCache = new Map();
  // Exposed for the Playwright e2e test to assert cache population.
  try { window.__socai_id_cache = _idCache; } catch (_) {}

  function _payloadField(p, dotted) {
    if (!p) return undefined;
    if (Object.prototype.hasOwnProperty.call(p, dotted)) return p[dotted];
    let v = p;
    for (const seg of dotted.split('.')) {
      if (v && typeof v === 'object' && seg in v) v = v[seg];
      else return undefined;
    }
    return v;
  }

  function _tsToMs(s) {
    if (!s) return null;
    const t = Date.parse(s);
    return Number.isFinite(t) ? t : null;
  }

  function _normalizeRowTimestamp(s) {
    // SO renders "2026-05-08 17:04:21.855 -04:00" (space before TZ).
    // Date.parse rejects that on some browsers; collapse the space.
    if (!s) return s;
    return s.replace(/\s+([+-]\d{2}:?\d{2})$/, '$1');
  }

  function _keyFromPayload(p) {
    const ts = _tsToMs(_payloadField(p, '@timestamp'));
    const ru = _payloadField(p, 'rule.uuid');
    if (ts === null || !ru) return null;
    const sip = _payloadField(p, 'source.ip') ?? '';
    const sport = String(_payloadField(p, 'source.port') ?? '');
    const dip = _payloadField(p, 'destination.ip') ?? '';
    const dport = String(_payloadField(p, 'destination.port') ?? '');
    return `${ts}|${ru}|${sip}|${sport}|${dip}|${dport}`;
  }

  function _keyFromRowCtx(ctx) {
    const tsRaw = ctx['Timestamp'] || ctx['@timestamp'] || '';
    const ts = _tsToMs(_normalizeRowTimestamp(tsRaw));
    const ru = ctx['rule.uuid'];
    if (ts === null || !ru) return null;
    const sip = ctx['source.ip'] || '';
    const sport = ctx['source.port'] || '';
    const dip = ctx['destination.ip'] || '';
    const dport = ctx['destination.port'] || '';
    return `${ts}|${ru}|${sip}|${sport}|${dip}|${dport}`;
  }

  function _ingestEventsBody(source, body) {
    try {
      const data = (typeof body === 'string') ? JSON.parse(body) : body;
      const events = (data && Array.isArray(data.events)) ? data.events : [];
      let added = 0;
      for (const ev of events) {
        if (!ev || !ev.id) continue;
        const key = _keyFromPayload(ev.payload || {});
        if (key) {
          _idCache.set(key, ev.id);
          added++;
        }
      }
      if (added > 0) {
        console.info('[soc-ai] cached', added, 'alert ids from', source, '(total:', _idCache.size, ')');
      } else if (events.length > 0) {
        // Surface why we didn't cache anything — most often missing rule.uuid
        // or @timestamp on the payloads, which would indicate a different
        // payload shape than expected.
        const sample = events[0] && events[0].payload ? Object.keys(events[0].payload).slice(0, 12) : [];
        console.warn('[soc-ai] saw', events.length, 'events from', source, 'but cached 0; payload keys (sample):', sample);
      }
    } catch (e) {
      console.warn('[soc-ai] could not parse body from', source, '-', String(e).slice(0, 120));
    }
  }

  // Patch fetch IMMEDIATELY (we're at document-start; SO bundle hasn't run
  // yet). Wrap-then-call so the underlying response object is unmodified for
  // the SO frontend.
  if (typeof window.fetch === 'function' && !window.__socai_fetch_patched) {
    const _origFetch = window.fetch.bind(window);
    window.fetch = async function patchedFetch(...args) {
      const resp = await _origFetch(...args);
      try {
        const url = (typeof args[0] === 'string')
          ? args[0]
          : (args[0] && args[0].url) || '';
        if (url && url.indexOf('/api/events/') !== -1) {
          // Clone before reading body — the SO frontend reads it once.
          resp.clone().text().then((body) => {
            _ingestEventsBody('fetch ' + url, body);
          }).catch((e) => {
            console.warn('[soc-ai] fetch clone read failed:', String(e).slice(0, 120));
          });
        }
      } catch (_e) { /* never break the page */ }
      return resp;
    };
    window.__socai_fetch_patched = true;
    console.info('[soc-ai] fetch patched at document-start');
  }

  // SO 3.0.0's frontend uses Axios under the hood, which goes through
  // XMLHttpRequest, not fetch. Patch XHR too.
  if (typeof window.XMLHttpRequest === 'function' && !window.__socai_xhr_patched) {
    const _OrigXHR = window.XMLHttpRequest;
    const _origOpen = _OrigXHR.prototype.open;
    const _origSend = _OrigXHR.prototype.send;
    _OrigXHR.prototype.open = function patchedOpen(method, url, ...rest) {
      try { this.__socai_url = url; } catch (_) {}
      return _origOpen.call(this, method, url, ...rest);
    };
    _OrigXHR.prototype.send = function patchedSend(...args) {
      try {
        const url = this.__socai_url || '';
        if (url && String(url).indexOf('/api/events/') !== -1) {
          this.addEventListener('load', () => {
            try {
              if (this.readyState === 4 && this.status >= 200 && this.status < 300) {
                _ingestEventsBody('xhr ' + url, this.responseText);
              }
            } catch (_e) {}
          });
        }
      } catch (_e) {}
      return _origSend.apply(this, args);
    };
    window.__socai_xhr_patched = true;
    console.info('[soc-ai] XMLHttpRequest patched at document-start');
  }

  // ---------------------------------------------------------------------------
  // Config
  // ---------------------------------------------------------------------------
  const DEFAULT_URL = 'https://localhost:8443';
  function getSocAiUrl() {
    return (typeof GM_getValue === 'function' ? GM_getValue('SOC_AI_URL', DEFAULT_URL) : DEFAULT_URL);
  }
  function setSocAiUrl(url) {
    if (typeof GM_setValue === 'function') GM_setValue('SOC_AI_URL', url);
  }
  // API token (v0.8.0): when soc-ai runs with API_AUTH_REQUIRED=true, every
  // request needs `Authorization: Bearer scai_…`. Mint a token in the soc-ai
  // config console (API Tokens) and paste it via the Tampermonkey menu command
  // "soc-ai: set API token". Stays empty (no header) for open deployments, so
  // this upgrade is backward-compatible.
  function getSocAiToken() {
    return (typeof GM_getValue === 'function' ? GM_getValue('SOC_AI_TOKEN', '') : '');
  }
  function setSocAiToken(token) {
    if (typeof GM_setValue === 'function') GM_setValue('SOC_AI_TOKEN', token || '');
  }
  function authHeaders() {
    const t = getSocAiToken();
    return t ? { Authorization: 'Bearer ' + t } : {};
  }

  // ---------------------------------------------------------------------------
  // Side panel + styles (v0.6.0 merged design)
  // ---------------------------------------------------------------------------
  // Sections: status strip (live), verdict card (post-synthesis), activity
  // timeline (compact, collapsible), footer (KPI + token sparkline + ctx %).
  // Header has a debug toggle that swaps the body for the raw JSON event log.
  const STYLE = `
:host { all: initial; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; }
.soc-ai-panel {
  position: fixed; right: 0; top: 0; bottom: 0; width: 540px;
  background: #0e1116; color: #d4d4dc; box-shadow: -4px 0 20px rgba(0,0,0,.45);
  z-index: 2147483646; display: flex; flex-direction: column;
  border-left: 1px solid #1f2330; font-size: 13px;
}
.soc-ai-header {
  display: flex; align-items: center; padding: 10px 14px;
  background: #181b25; border-bottom: 1px solid #1f2330;
  font-size: 13px; font-weight: 600;
}
.soc-ai-title { flex: 1; color: #e6e6ed; }
.soc-ai-btn {
  background: #1f2330; color: #d4d4dc; border: 1px solid #2c3142;
  padding: 3px 9px; border-radius: 3px; font-size: 11px; cursor: pointer;
  margin-left: 4px;
}
.soc-ai-btn:hover { background: #2c3142; }
.soc-ai-btn.primary { background: #2563eb; border-color: #1d4ed8; color: white; }
.soc-ai-btn.primary:hover { background: #1d4ed8; }
.soc-ai-btn.danger { background: #1f2330; border-color: #b91c1c; color: #fca5a5; }
.soc-ai-btn.danger:hover { background: #b91c1c; color: white; }
.soc-ai-btn.active { background: #2c3142; border-color: #2563eb; color: #93c5fd; }

.soc-ai-body { flex: 1; overflow-y: auto; }
.soc-ai-section { padding: 10px 14px; border-bottom: 1px solid #1f2330; }
.soc-ai-section:last-child { border-bottom: none; }
.soc-ai-label {
  font-size: 10px; color: #6b7280; text-transform: uppercase;
  letter-spacing: 0.5px; margin-bottom: 6px;
  display: flex; align-items: center; gap: 4px;
}
.soc-ai-label-spacer { flex: 1; }

/* Status strip */
.soc-ai-status { background: linear-gradient(180deg, #181b25, #14181f); }
.soc-ai-status-row { display: flex; align-items: center; gap: 6px; margin-bottom: 6px; }
.soc-ai-status-phase { font-size: 12px; font-weight: 600; }
.soc-ai-status-time { font-size: 11px; color: #6b7280; }
.soc-ai-status-now {
  font-size: 11px; color: #9ca3af; margin-top: 5px;
  overflow: hidden; white-space: nowrap; text-overflow: ellipsis;
}
.soc-ai-status-now-tool { color: #06b6d4; font-weight: 600; }
.soc-ai-progress { height: 5px; background: #1f2330; border-radius: 2px; overflow: hidden; }
.soc-ai-progress-fill {
  height: 100%; background: linear-gradient(90deg, #2563eb, #a855f7);
  transition: width 200ms ease-out; width: 0%;
}
.soc-ai-progress-fill.done { background: linear-gradient(90deg, #10b981, #06b6d4); }
.soc-ai-progress-fill.error { background: linear-gradient(90deg, #b91c1c, #f59e0b); }
.soc-ai-spinner {
  display: inline-block; width: 11px; height: 11px;
  border: 2px solid #2563eb; border-top-color: transparent;
  border-radius: 50%; vertical-align: middle;
  animation: socai-spin 0.8s linear infinite;
}
@keyframes socai-spin { to { transform: rotate(360deg); } }
.soc-ai-check { color: #10b981; font-weight: 700; font-size: 14px; }
.soc-ai-warn { color: #fbbf24; font-weight: 700; }
.soc-ai-x { color: #fca5a5; font-weight: 700; }

/* Verdict card */
.soc-ai-verdict { background: linear-gradient(180deg, #11151c, #0e1116); padding: 14px; }
.soc-ai-verdict.hidden { display: none; }
.soc-ai-verdict-row { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
.soc-ai-pill {
  display: inline-block; padding: 4px 12px; border-radius: 12px;
  font-size: 11px; font-weight: 700; letter-spacing: 0.4px;
  text-transform: uppercase;
}
.soc-ai-pill.true_positive { background: #b91c1c; color: white; }
.soc-ai-pill.false_positive { background: #065f46; color: white; }
.soc-ai-pill.needs_more_info { background: #b45309; color: white; }
.soc-ai-confidence { font-size: 11px; color: #9ca3af; line-height: 1.2; }
.soc-ai-conf-bar {
  height: 3px; background: #1f2330; border-radius: 2px; overflow: hidden;
  margin-top: 3px;
}
.soc-ai-conf-fill { height: 100%; background: #10b981; }

.soc-ai-summary {
  font-size: 12px; line-height: 1.5; color: #d4d4dc;
  margin-bottom: 10px;
}

.soc-ai-rec-label {
  font-size: 9px; font-weight: 700; color: #fbbf24;
  text-transform: uppercase; letter-spacing: 0.5px;
  margin-bottom: 4px;
}
.soc-ai-rationale {
  font-size: 12px; line-height: 1.5; color: #fde68a;
  background: rgba(251,191,36,0.08);
  padding: 8px 10px; border-radius: 4px;
  border-left: 3px solid #fbbf24; margin-bottom: 8px;
}
.soc-ai-actions { display: flex; gap: 6px; flex-wrap: wrap; }
.soc-ai-action-result { font-size: 11px; margin-top: 6px; }
.soc-ai-action-result.ok { color: #10b981; }
.soc-ai-action-result.err { color: #fca5a5; }

.soc-ai-citations { font-size: 10px; color: #6b7280; margin-top: 10px; }
.soc-ai-citation {
  display: inline-block; background: #1f2330; padding: 1px 6px;
  border-radius: 3px; font-family: ui-monospace, monospace;
  font-size: 10px; margin: 2px 3px 2px 0;
  color: #9ca3af;
}

/* Activity timeline */
.soc-ai-events { max-height: 280px; overflow-y: auto; }
.soc-ai-events.collapsed { display: none; }
.soc-ai-event {
  font-size: 11px; padding: 3px 0; color: #9ca3af; line-height: 1.4;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.soc-ai-event-icon {
  display: inline-block; width: 16px; text-align: center;
  margin-right: 4px;
}
.soc-ai-event.session_start .soc-ai-event-icon { color: #6b7280; }
.soc-ai-event.alert_context .soc-ai-event-icon { color: #06b6d4; }
.soc-ai-event.tool_call .soc-ai-event-icon { color: #06b6d4; }
.soc-ai-event.tool_result .soc-ai-event-icon { color: #10b981; }
.soc-ai-event.model_response .soc-ai-event-icon { color: #a855f7; }
.soc-ai-event.investigation_transcript .soc-ai-event-icon { color: #a855f7; }
.soc-ai-event.usage .soc-ai-event-icon { color: #6b7280; }
.soc-ai-event.retask .soc-ai-event-icon { color: #fbbf24; }
.soc-ai-event.error { color: #fca5a5; }
.soc-ai-event.error .soc-ai-event-icon { color: #fca5a5; }
.soc-ai-event.thinking { color: #6b7280; font-style: italic; }
.soc-ai-event.expanded { white-space: normal; }
.soc-ai-event.expandable { cursor: pointer; }
.soc-ai-event.expandable:hover { color: #d4d4dc; }
.soc-ai-event-trace {
  display: block; margin-top: 4px; padding: 6px 8px;
  background: #0a0c10; border-radius: 3px;
  font-family: ui-monospace, monospace; font-size: 10px;
  color: #6b7280; white-space: pre-wrap; line-height: 1.4;
}

/* Footer KPIs + sparkline */
.soc-ai-footer { background: #0a0c10; padding: 10px 14px; }
.soc-ai-kpis { display: flex; gap: 14px; font-size: 11px; color: #9ca3af; }
.soc-ai-kpi-icon { color: #6b7280; margin-right: 3px; }
.soc-ai-kpi-tools { cursor: pointer; user-select: none; }
.soc-ai-kpi-tools:hover { color: #d1d5db; }
.soc-ai-tools-detail {
  margin-top: 8px; font-size: 11px; color: #9ca3af;
  max-height: 168px; overflow-y: auto;
  border-top: 1px solid #1f2430; padding-top: 6px;
}
.soc-ai-tools-detail.hidden { display: none; }
.soc-ai-tools-detail-item { padding: 2px 0; display: flex; gap: 8px; }
.soc-ai-tools-detail-item .k { color: #6b7280; flex: 0 0 64px; text-align: right; }
.soc-ai-tools-detail-item .v { color: #cbd5e1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.soc-ai-tools-detail-empty { color: #6b7280; font-style: italic; }
.soc-ai-spark { margin-top: 6px; }
.soc-ai-sparkline { width: 100%; height: 22px; display: block; }
.soc-ai-spark-meta {
  display: flex; justify-content: space-between;
  font-size: 9px; color: #6b7280; margin-top: 2px;
}
.soc-ai-ctx-warn { color: #fbbf24; font-weight: 600; }
.soc-ai-ctx-crit { color: #fca5a5; font-weight: 600; }

/* Debug pane (raw JSON dump) */
.soc-ai-debug { display: none; }
.soc-ai-debug.active { display: block; }
.soc-ai-debug pre {
  font-family: ui-monospace, "JetBrains Mono", "SF Mono", monospace;
  font-size: 10px; line-height: 1.4; color: #9ca3af;
  background: #0a0c10; padding: 8px 12px;
  white-space: pre-wrap; word-break: break-word;
  margin: 0;
}
.soc-ai-debug-event {
  border-left: 2px solid #1f2330; padding-left: 8px; margin: 6px 0;
}
.soc-ai-debug-kind {
  font-size: 9px; text-transform: uppercase; letter-spacing: 0.5px;
  color: #6b7280; margin-bottom: 2px;
}
.soc-ai-panel.debug-mode .soc-ai-section.live { display: none; }
.soc-ai-panel.debug-mode .soc-ai-debug { display: block; }

/* Hunt button on rows (unchanged) */
.soc-ai-button.hunt {
  position: relative; padding: 4px 8px; margin-left: 4px;
  background: linear-gradient(135deg, #2563eb 0%, #7c3aed 100%);
  color: white; border: none; border-radius: 3px; cursor: pointer;
  font-size: 11px; font-weight: 600;
}
.soc-ai-button.hunt:hover { opacity: 0.9; }
`;

  // ---------------------------------------------------------------------------
  // Panel logic — v0.6.0 merged design
  // ---------------------------------------------------------------------------
  // The panel is built once (`ensurePanel`) and reset per investigation
  // (`resetPanel`). Each SSE event drives a small state machine that
  // updates the relevant section in place. No more JSON-blob-per-event;
  // raw JSON is preserved in a hidden debug pane that the header toggle
  // swaps in.

  let host = null;
  let panelEl = null;
  let bodyEl = null;
  let dom = {};      // cached references to live-section sub-elements
  let state = null;  // per-investigation state, see _newState
  let elapsedTimer = null;
  const MAX_CTX_TOKENS = 64 * 1024;
  // Phase ordering for the progress bar; the index of the current phase
  // determines fill width (so user sees forward progress).
  const PHASE_ORDER = ['prefetch', 'investigator', 'synthesizer', 'retask', 'done'];

  function _newState(alertId) {
    return {
      alertId,
      startTime: Date.now(),
      phase: 'prefetch',
      round: 1,
      currentTool: null,
      toolCount: 0,
      toolDetails: [],    // [{kind, label}] backing the clickable #tools breakdown
      requestCount: 0,
      tokensIn: 0,
      tokensOut: 0,
      tokenSeries: [],   // [{t, total}]
      perPhaseTokens: {}, // { "investigator-1": {in,out}, ... }
      events: [],         // for the debug pane
      verdictReceived: false,
      done: false,
      error: false,
      pendingApprovals: [], // {token, tool_name, tool_args, rationale}
      report: null,
    };
  }

  function _isDebugMode() {
    try { return localStorage.getItem('socaiDebug') === '1'; } catch (_) { return false; }
  }
  function _setDebugMode(on) {
    try { localStorage.setItem('socaiDebug', on ? '1' : '0'); } catch (_) {}
    if (panelEl) panelEl.classList.toggle('debug-mode', !!on);
    if (dom.debugBtn) dom.debugBtn.classList.toggle('active', !!on);
  }

  function ensurePanel() {
    if (host) return;
    host = document.createElement('div');
    host.id = 'soc-ai-host';
    host.attachShadow({ mode: 'open' });
    const styleEl = document.createElement('style');
    styleEl.textContent = STYLE;
    host.shadowRoot.appendChild(styleEl);

    panelEl = document.createElement('div');
    panelEl.className = 'soc-ai-panel';
    panelEl.innerHTML = `
      <div class="soc-ai-header">
        <span class="soc-ai-title">🔍 Hunt with AI</span>
        <button class="soc-ai-btn" data-act="config" title="Configure base URL">⚙</button>
        <button class="soc-ai-btn" data-act="debug" title="Toggle raw JSON debug view">debug</button>
        <button class="soc-ai-btn" data-act="close" title="Close panel">✕</button>
      </div>
      <div class="soc-ai-body">
        <!-- Status strip -->
        <section class="soc-ai-section soc-ai-status live" data-section="status">
          <div class="soc-ai-status-row">
            <span class="soc-ai-status-icon"></span>
            <span class="soc-ai-status-phase">Starting…</span>
            <span class="soc-ai-label-spacer"></span>
            <span class="soc-ai-status-time">0s</span>
          </div>
          <div class="soc-ai-progress"><div class="soc-ai-progress-fill"></div></div>
          <div class="soc-ai-status-now"></div>
        </section>
        <!-- Verdict card (hidden until triage_report) -->
        <section class="soc-ai-section soc-ai-verdict live hidden" data-section="verdict"></section>
        <!-- Activity timeline -->
        <section class="soc-ai-section live" data-section="activity">
          <div class="soc-ai-label">
            Activity
            <span class="soc-ai-label-spacer"></span>
            <button class="soc-ai-btn" data-act="collapse">▾ <span data-act="count">0</span></button>
          </div>
          <div class="soc-ai-events"></div>
        </section>
        <!-- Footer -->
        <footer class="soc-ai-section soc-ai-footer live">
          <div class="soc-ai-kpis">
            <span class="soc-ai-kpi-tools" data-act="tools-toggle" title="Click to see which tools / evidence-gathering ran"><span class="soc-ai-kpi-icon">🛠</span> <span data-kpi="tools">0</span> tools <span data-tools-caret>▾</span></span>
            <span><span class="soc-ai-kpi-icon">📊</span> <span data-kpi="tokens">0</span></span>
            <span><span class="soc-ai-kpi-icon">⏱</span> <span data-kpi="elapsed">0s</span></span>
          </div>
          <div class="soc-ai-tools-detail hidden" data-tools-detail></div>
          <div class="soc-ai-spark">
            <svg class="soc-ai-sparkline" viewBox="0 0 100 22" preserveAspectRatio="none">
              <path data-spark="fill" d="" fill="rgba(168,85,247,0.15)"></path>
              <path data-spark="line" d="" stroke="#a855f7" stroke-width="1.5" fill="none"></path>
            </svg>
            <div class="soc-ai-spark-meta">
              <span data-spark-meta="left">tokens · cumulative</span>
              <span data-spark-meta="right">0% of 64k ctx</span>
            </div>
          </div>
        </footer>
        <!-- Debug pane (hidden when not active) -->
        <div class="soc-ai-debug"></div>
      </div>
    `;
    host.shadowRoot.appendChild(panelEl);
    document.body.appendChild(host);

    bodyEl = panelEl.querySelector('.soc-ai-body');
    dom = {
      statusIcon:   panelEl.querySelector('.soc-ai-status-icon'),
      statusPhase:  panelEl.querySelector('.soc-ai-status-phase'),
      statusTime:   panelEl.querySelector('.soc-ai-status-time'),
      statusNow:    panelEl.querySelector('.soc-ai-status-now'),
      progressFill: panelEl.querySelector('.soc-ai-progress-fill'),
      verdict:      panelEl.querySelector('[data-section="verdict"]'),
      events:       panelEl.querySelector('[data-section="activity"] .soc-ai-events'),
      eventsCount:  panelEl.querySelector('[data-act="count"]'),
      collapseBtn:  panelEl.querySelector('[data-act="collapse"]'),
      kpiTools:     panelEl.querySelector('[data-kpi="tools"]'),
      kpiToolsBtn:  panelEl.querySelector('[data-act="tools-toggle"]'),
      toolsDetail:  panelEl.querySelector('[data-tools-detail]'),
      toolsCaret:   panelEl.querySelector('[data-tools-caret]'),
      kpiTokens:    panelEl.querySelector('[data-kpi="tokens"]'),
      kpiElapsed:   panelEl.querySelector('[data-kpi="elapsed"]'),
      sparkLine:    panelEl.querySelector('[data-spark="line"]'),
      sparkFill:    panelEl.querySelector('[data-spark="fill"]'),
      sparkLeft:    panelEl.querySelector('[data-spark-meta="left"]'),
      sparkRight:   panelEl.querySelector('[data-spark-meta="right"]'),
      debugPane:    panelEl.querySelector('.soc-ai-debug'),
      debugBtn:     panelEl.querySelector('[data-act="debug"]'),
    };

    panelEl.querySelector('[data-act="close"]').onclick = () => {
      host.style.display = 'none';
    };
    panelEl.querySelector('[data-act="config"]').onclick = () => {
      const cur = getSocAiUrl();
      const next = window.prompt('soc-ai base URL:', cur);
      if (next) setSocAiUrl(next.trim());
    };
    dom.debugBtn.onclick = () => _setDebugMode(!_isDebugMode());
    dom.kpiToolsBtn.onclick = () => {
      dom.toolsDetail.classList.toggle('hidden');
      const visible = !dom.toolsDetail.classList.contains('hidden');
      dom.toolsCaret.textContent = visible ? '▴' : '▾';
      if (visible) _renderToolsDetail();
    };
    dom.collapseBtn.onclick = () => {
      dom.events.classList.toggle('collapsed');
      dom.collapseBtn.firstChild.textContent =
        dom.events.classList.contains('collapsed') ? '▸ ' : '▾ ';
    };

    _setDebugMode(_isDebugMode());  // restore from localStorage
  }

  function showPanel() { if (host) host.style.display = ''; }

  function resetPanel(alertId) {
    state = _newState(alertId);
    dom.statusIcon.innerHTML = '<span class="soc-ai-spinner"></span>';
    dom.statusPhase.textContent = 'Starting…';
    dom.statusTime.textContent = '0s';
    dom.statusNow.textContent = '';
    dom.progressFill.className = 'soc-ai-progress-fill';
    dom.progressFill.style.width = '4%';
    dom.verdict.classList.add('hidden');
    dom.verdict.innerHTML = '';
    dom.events.innerHTML = '';
    dom.events.classList.remove('collapsed');
    dom.eventsCount.textContent = '0';
    dom.collapseBtn.firstChild.textContent = '▾ ';
    dom.kpiTools.textContent = '0';
    dom.toolsDetail.innerHTML = '';
    dom.toolsDetail.classList.add('hidden');
    dom.toolsCaret.textContent = '▾';
    dom.kpiTokens.textContent = '0';
    dom.kpiElapsed.textContent = '0s';
    dom.sparkLine.setAttribute('d', '');
    dom.sparkFill.setAttribute('d', '');
    dom.sparkLeft.textContent = 'tokens · cumulative';
    dom.sparkRight.textContent = '0% of 64k ctx';
    dom.debugPane.innerHTML = '';
    if (elapsedTimer) clearInterval(elapsedTimer);
    elapsedTimer = setInterval(_tickElapsed, 1000);
  }

  function _formatElapsed(ms) {
    const s = Math.floor(ms / 1000);
    if (s < 60) return s + 's';
    const m = Math.floor(s / 60);
    const r = s % 60;
    return r === 0 ? m + 'm' : m + 'm ' + r + 's';
  }
  function _tickElapsed() {
    if (!state) return;
    const ms = Date.now() - state.startTime;
    dom.statusTime.textContent = _formatElapsed(ms);
    dom.kpiElapsed.textContent = _formatElapsed(ms);
  }

  // ---- #tools KPI breakdown -------------------------------------------------
  // The footer "🛠 N tools" counts evidence-gathering work: prefetch pivots +
  // enriched indicators (synth-first makes no agent tool calls), plus any
  // Phase-D dispatch or legacy investigator tool calls. Clicking the KPI shows
  // exactly what ran. Labels carry server/LLM data → render via textContent.
  function _firstArg(args) {
    try {
      const a = (typeof args === 'string') ? JSON.parse(args) : (args || {});
      const k = Object.keys(a)[0];
      return k ? (k + '=' + _short(String(a[k]), 36)) : '';
    } catch (_) { return ''; }
  }
  function _pushTool(kind, label) {
    if (!state) return;
    state.toolDetails.push({ kind: kind, label: label });
    if (dom.toolsDetail && !dom.toolsDetail.classList.contains('hidden')) _renderToolsDetail();
  }
  function _renderToolsDetail() {
    const items = (state && state.toolDetails) || [];
    dom.toolsDetail.innerHTML = '';
    if (!items.length) {
      const empty = document.createElement('div');
      empty.className = 'soc-ai-tools-detail-empty';
      empty.textContent = 'No tools have run yet.';
      dom.toolsDetail.appendChild(empty);
      return;
    }
    for (const it of items) {
      const row = document.createElement('div');
      row.className = 'soc-ai-tools-detail-item';
      const k = document.createElement('span');
      k.className = 'k';
      k.textContent = it.kind;
      const v = document.createElement('span');
      v.className = 'v';
      v.textContent = it.label;   // textContent → XSS-safe
      row.appendChild(k);
      row.appendChild(v);
      dom.toolsDetail.appendChild(row);
    }
  }

  function _short(s, n) {
    if (typeof s !== 'string') s = JSON.stringify(s);
    s = s.replace(/\s+/g, ' ').trim();
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }

  function _phaseLabel(phase, round) {
    if (phase === 'prefetch') return 'Pre-fetching alert…';
    if (phase === 'investigator') return 'Investigator · round ' + round;
    if (phase === 'synthesizer') return 'Synthesizing · round ' + round;
    if (phase === 'retask') return 'Retasking…';
    if (phase === 'done') return 'Triage complete';
    if (phase === 'error') return 'Error';
    return phase;
  }

  function _setProgress(phase, sub) {
    // sub: 0..1 progress within the phase
    const idx = PHASE_ORDER.indexOf(phase);
    if (idx < 0) return;
    const slot = 1 / PHASE_ORDER.length;
    const pct = Math.min(98, ((idx + (sub || 0.5)) * slot) * 100);
    dom.progressFill.style.width = pct.toFixed(1) + '%';
  }

  function _updateStatusForPhase() {
    if (!state) return;
    dom.statusPhase.textContent = _phaseLabel(state.phase, state.round);
    if (state.error) {
      dom.statusIcon.innerHTML = '<span class="soc-ai-x">⚠</span>';
    } else if (state.done) {
      dom.statusIcon.innerHTML = '<span class="soc-ai-check">✓</span>';
    } else {
      dom.statusIcon.innerHTML = '<span class="soc-ai-spinner"></span>';
    }
  }

  // Cap the activity timeline + debug pane so a chatty investigation
  // (30+ tool calls) doesn't bloat the shadow DOM and keep the browser
  // re-painting hundreds of children.
  const MAX_TIMELINE_ROWS = 200;
  const MAX_DEBUG_ROWS = 200;

  function _addEvent(kind, payload, opts) {
    state.events.push({ kind, payload, ts: Date.now() });
    _appendDebugEvent(kind, payload);

    // Cap the in-memory event log too — only the visible window matters.
    if (state.events.length > MAX_TIMELINE_ROWS * 2) {
      state.events.splice(0, state.events.length - MAX_TIMELINE_ROWS * 2);
    }

    const el = document.createElement('div');
    el.className = 'soc-ai-event ' + kind;
    el.innerHTML = '<span class="soc-ai-event-icon"></span><span></span>';
    const icon = el.firstChild;
    const txt = el.lastChild;
    icon.textContent = (opts && opts.icon) || _eventIcon(kind);
    txt.textContent = (opts && opts.text) || kind;
    if (opts && opts.trace) {
      const t = document.createElement('span');
      t.className = 'soc-ai-event-trace';
      t.textContent = opts.trace;
      el.classList.add('expandable');
      el.appendChild(t);
      t.style.display = 'none';
      el.onclick = () => {
        el.classList.toggle('expanded');
        t.style.display = el.classList.contains('expanded') ? 'block' : 'none';
      };
    }
    dom.events.appendChild(el);
    // Trim oldest rows beyond the cap. The DOM is the bottleneck; iterate
    // children list and remove from the front.
    while (dom.events.children.length > MAX_TIMELINE_ROWS) {
      dom.events.removeChild(dom.events.firstChild);
    }
    dom.events.scrollTop = dom.events.scrollHeight;
    dom.eventsCount.textContent = String(state.events.length);
  }

  function _eventIcon(kind) {
    return ({
      session_start: '▶',
      alert_context: '◉',
      tool_call: '⚡',
      tool_result: '↳',
      model_response: '…',
      investigation_transcript: '📋',
      usage: '📊',
      retask: '🔁',
      triage_report: '🎯',
      approval_required: '🔒',
      done: '✓',
      error: '⚠',
    })[kind] || '·';
  }

  function _appendDebugEvent(kind, payload) {
    const div = document.createElement('div');
    div.className = 'soc-ai-debug-event';
    div.innerHTML = '<div class="soc-ai-debug-kind"></div><pre></pre>';
    div.firstChild.textContent = kind;
    div.lastChild.textContent = JSON.stringify(payload, null, 2);
    dom.debugPane.appendChild(div);
    while (dom.debugPane.children.length > MAX_DEBUG_ROWS) {
      dom.debugPane.removeChild(dom.debugPane.firstChild);
    }
  }

  function _renderSparkline() {
    if (!state || state.tokenSeries.length === 0) return;
    const series = state.tokenSeries;
    const maxTotal = Math.max(...series.map(p => p.total), 1);
    const W = 100, H = 22;
    let line = '', fill = '';
    series.forEach((p, i) => {
      const x = series.length === 1 ? W : (i / (series.length - 1)) * W;
      const y = H - (p.total / maxTotal) * (H - 2) - 1;
      line += (i === 0 ? 'M' : ' L') + x.toFixed(1) + ',' + y.toFixed(1);
    });
    fill = line + ` L${W},${H} L0,${H} Z`;
    dom.sparkLine.setAttribute('d', line);
    dom.sparkFill.setAttribute('d', fill);

    const total = state.tokensIn + state.tokensOut;
    const pct = (total / MAX_CTX_TOKENS) * 100;
    dom.sparkLeft.textContent =
      'in: ' + _kfmt(state.tokensIn) + ' · out: ' + _kfmt(state.tokensOut);
    dom.sparkRight.innerHTML =
      pct < 60 ? pct.toFixed(0) + '% of 64k ctx'
      : pct < 85 ? '<span class="soc-ai-ctx-warn">' + pct.toFixed(0) + '% of 64k ctx</span>'
      : '<span class="soc-ai-ctx-crit">' + pct.toFixed(0) + '% of 64k ctx</span>';
  }

  function _kfmt(n) {
    n = Number(n) || 0;
    if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
    return String(n);
  }

  function _renderVerdict() {
    if (!state || !state.report) return;
    const r = state.report;
    dom.verdict.classList.remove('hidden');
    const conf = (r.confidence != null) ? r.confidence : 0;
    const confPct = Math.round(conf * 100);
    const rationale = (r.recommended_actions && r.recommended_actions.length)
      ? r.recommended_actions[0].rationale
      : null;
    const cites = (r.citations || []).slice(0, 6)
      .map(c => '<span class="soc-ai-citation"></span>');
    dom.verdict.innerHTML = `
      <div class="soc-ai-verdict-row">
        <span class="soc-ai-pill ${r.verdict}"></span>
        <div style="flex:1">
          <div class="soc-ai-confidence">confidence ${conf.toFixed(2)} (${confPct}%)</div>
          <div class="soc-ai-conf-bar"><div class="soc-ai-conf-fill" style="width:${confPct}%"></div></div>
        </div>
      </div>
      <div class="soc-ai-summary"></div>
      ${rationale ? '<div class="soc-ai-rec-label">Recommendation</div><div class="soc-ai-rationale"></div>' : ''}
      <div class="soc-ai-actions"></div>
      ${(r.citations && r.citations.length) ? '<div class="soc-ai-citations">cites: ' + cites.join(' ') + '</div>' : ''}
    `;
    // Set text-content on the placeholder spans (avoids HTML-injection from the model output).
    const verdictPill = dom.verdict.querySelector('.soc-ai-pill');
    if (verdictPill) verdictPill.textContent = (r.verdict || '').replace(/_/g, ' ').toUpperCase();
    const summaryEl = dom.verdict.querySelector('.soc-ai-summary');
    if (summaryEl) summaryEl.textContent = r.summary || '';
    const ratEl = dom.verdict.querySelector('.soc-ai-rationale');
    if (ratEl) ratEl.textContent = rationale || '';
    const cWrap = dom.verdict.querySelector('.soc-ai-citations');
    if (cWrap && r.citations) {
      cWrap.querySelectorAll('.soc-ai-citation').forEach((sp, i) => {
        sp.textContent = r.citations[i] || '';
      });
    }
    _renderActions();
  }

  function _renderActions() {
    if (!state || !state.report) return;
    const actionsEl = dom.verdict.querySelector('.soc-ai-actions');
    if (!actionsEl) return;
    actionsEl.innerHTML = '';
    if (state.pendingApprovals.length === 0) return;
    state.pendingApprovals.forEach(p => {
      const wrap = document.createElement('span');
      wrap.style.cssText = 'display:flex;gap:5px;align-items:center;flex-wrap:wrap';
      const ok = document.createElement('button');
      ok.className = 'soc-ai-btn primary';
      ok.textContent = 'Approve ' + (p.tool_name || 'action');
      const no = document.createElement('button');
      no.className = 'soc-ai-btn danger';
      no.textContent = 'Reject';
      const result = document.createElement('span');
      result.className = 'soc-ai-action-result';
      const handle = async (approved) => {
        ok.disabled = true; no.disabled = true;
        result.textContent = ' submitting…';
        result.className = 'soc-ai-action-result';
        const reason = approved ? null : (window.prompt('Reason for rejection (optional):', '') || null);
        const data = await decide(p.token, approved, reason);
        if (data && data.error) {
          result.textContent = ' ' + (data.status || 'error') + ': ' + data.error;
          result.className = 'soc-ai-action-result err';
        } else if (data) {
          result.textContent = ' ' + (data.status || 'ok');
          result.className = 'soc-ai-action-result ok';
        } else {
          result.textContent = ' request failed';
          result.className = 'soc-ai-action-result err';
        }
      };
      ok.onclick = () => handle(true);
      no.onclick = () => handle(false);
      wrap.appendChild(ok);
      wrap.appendChild(no);
      wrap.appendChild(result);
      actionsEl.appendChild(wrap);
    });
  }

  async function decide(token, approved, reason) {
    const url = getSocAiUrl().replace(/\/$/, '') + '/approve';
    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ token, approved, reason: reason || null }),
      });
      const data = await resp.json().catch(() => null);
      return data;
    } catch (e) {
      return { status: 'error', error: String(e) };
    }
  }

  // ---------------------------------------------------------------------------
  // SSE event router — drives the panel state machine
  // ---------------------------------------------------------------------------
  function handleSseEvent(kind, payload) {
    if (!state) return;
    switch (kind) {
      case 'session_start': {
        state.phase = 'prefetch';
        _updateStatusForPhase();
        _setProgress('prefetch', 0.5);
        _addEvent(kind, payload, {
          text: 'Started · ' + _short(payload.alert_id || '?', 24),
        });
        break;
      }
      case 'alert_context': {
        const a = payload.alert || {};
        const ps = payload.pivot_summary || {};
        const piv = Object.entries(ps).filter(([_, v]) => v).map(([k, v]) => k + ':' + v).join(', ');
        _addEvent(kind, payload, {
          text: (a.severity_label || '?') + ' · ' +
                (a.rule_name || '(no rule)') +
                (piv ? ' · pivots[' + piv + ']' : ''),
        });
        // Implies prefetch is done; investigator round 1 next.
        state.phase = 'investigator';
        state.round = 1;
        _setProgress('investigator', 0.1);
        _updateStatusForPhase();
        break;
      }
      // ----- synth-first pipeline events (v0.7.0) -------------------------
      // The synth-first pipeline (default since 2026-05-28) emits a
      // different event set than the legacy investigator. Prefetch is a
      // single enriched_alert_context; there's no per-round investigator
      // transcript — the synth reasons from the prefetch + an optional
      // single Phase-D tool dispatch.
      case 'enriched_alert_context': {
        const a = payload.alert || {};
        const ps = payload.pivot_summary || {};
        const piv = Object.entries(ps).filter(([_, v]) => v)
          .map(([k, v]) => k + ':' + v).join(', ');
        const enr = payload.enrichments || {};
        let hits = 0;
        for (const k in enr) {
          const e = enr[k] || {};
          hits += (e.blocklist_hits || []).length + (e.misp_hits || []).length;
        }
        // Synth-first gathers evidence deterministically (no agent tool
        // calls on the fast path), so the "tools" KPI stayed at 0. Surface
        // the prefetch work instead: pivot records + enriched indicators.
        // Count one entry per evidence-gathering item — must equal the number of
        // rows in the clickable breakdown (per-pivot event counts live in the labels).
        const pivotFields = Object.entries(ps).filter(([_, v]) => Number(v) > 0);
        state.toolCount = pivotFields.length + Object.keys(enr).length;
        dom.kpiTools.textContent = String(state.toolCount);
        // Breakdown for the clickable #tools KPI: which pivots ran + what got enriched.
        for (const [field, n] of pivotFields) {
          _pushTool('pivot', field + ' (' + n + ' event' + (Number(n) > 1 ? 's' : '') + ')');
        }
        for (const ind in enr) {
          const e = enr[ind] || {};
          const nhits = (e.blocklist_hits || []).length + (e.misp_hits || []).length;
          _pushTool('enrich', ind + (nhits ? ' · ' + nhits + ' IOC hit' + (nhits > 1 ? 's' : '') : ''));
        }
        _addEvent(kind, payload, {
          text: (a.rule_name || a['rule.name'] || '(no rule)') +
                ' · ' + Object.keys(enr).length + ' enriched' +
                (hits ? ' · ' + hits + ' IOC hit' + (hits > 1 ? 's' : '') : '') +
                (piv ? ' · pivots[' + piv + ']' : ''),
          icon: '◉',
        });
        // Prefetch done; the synth does the reasoning (no investigator round).
        state.phase = 'synthesizer';
        state.round = 1;
        _setProgress('synthesizer', 0.2);
        _updateStatusForPhase();
        break;
      }
      case 'decision_template_match': {
        _addEvent(kind, payload, {
          text: payload.matched
            ? 'template: ' + (payload.template_id || '?') + ' → ' +
              (payload.verdict || '?') +
              (payload.confidence != null ? ' (' + payload.confidence.toFixed(2) + ')' : '')
            : 'no template matched — synth reasons from context',
          trace: payload.rationale || null,
          icon: '▦',
        });
        break;
      }
      case 'targeted_dispatch': {
        state.toolCount++;
        dom.kpiTools.textContent = String(state.toolCount);
        const tdArg = _firstArg(payload.tool_args);
        _pushTool('phase-d', (payload.tool_name || '?') + (tdArg ? '(' + tdArg + ')' : ''));
        _addEvent(kind, payload, {
          text: 'Phase D: ' + (payload.tool_name || '?') +
                (payload.question ? ' · ' + _short(payload.question, 70) : ''),
          trace: payload.why_this_matters || null,
          icon: '⚡',
        });
        _setProgress('synthesizer', 0.5);
        break;
      }
      case 'targeted_tool_result': {
        const r = payload.result;
        let summary;
        if (r == null) summary = 'null';
        else if (Array.isArray(r)) summary = r.length + ' rows';
        else if (typeof r === 'object') summary = _short(JSON.stringify(r), 60);
        else summary = _short(String(r), 60);
        _addEvent(kind, payload, {
          text: (payload.tool_name || '?') + ' → ' + summary,
          icon: '↳',
        });
        break;
      }
      // Post-synth validators — compact, muted "checks applied" lines.
      case 'citation_validation': {
        const cov = payload.coverage_ratio;
        const c = payload.counts || {};
        _addEvent(kind, payload, {
          text: 'citations: ' + (c.valid != null ? c.valid : '?') + '/' +
                (payload.total || 0) + ' resolved' +
                (cov != null ? ' (' + Math.round(cov * 100) + '% coverage)' : ''),
          icon: '✓',
        });
        break;
      }
      case 'citation_cap':
      case 'template_ceiling': {
        const o = payload.original_confidence;
        const n = payload.capped_confidence;
        _addEvent(kind, payload, {
          text: (kind === 'citation_cap' ? 'citation cap' : 'template ceiling') +
                ': conf ' + (o != null ? o.toFixed(2) : '?') +
                ' → ' + (n != null ? n.toFixed(2) : '?'),
          icon: '↧',
        });
        break;
      }
      case 'verdict_floor_rewrite': {
        _addEvent(kind, payload, {
          text: 'verdict floored → needs_more_info' +
                (payload.confidence != null ? ' (conf ' + payload.confidence.toFixed(2) + ')' : ''),
          trace: payload.reason || null,
          icon: '↧',
        });
        break;
      }
      case 'icmp_solicited_downgrade': {
        _addEvent(kind, payload, {
          text: 'downgraded ' + (payload.original_verdict || 'true_positive') +
                ' → ' + (payload.downgraded_verdict || 'false_positive') +
                ' · solicited ICMP echo reply (benign ping)',
          trace: payload.reason || null,
          icon: '↩',
        });
        break;
      }
      case 'tool_call': {
        state.toolCount++;
        state.currentTool = payload.tool_name;
        state.phase = (payload.phase === 'synthesizer' ? 'synthesizer' : (state.phase || 'investigator'));
        if (typeof payload.round === 'number') state.round = payload.round;
        dom.kpiTools.textContent = String(state.toolCount);
        let argsLabel = '';
        try {
          const args = (typeof payload.args === 'string') ? JSON.parse(payload.args) : (payload.args || {});
          const k = Object.keys(args)[0];
          argsLabel = k ? (k + '=' + _short(String(args[k]), 40)) : '';
        } catch (_) {}
        _pushTool('tool', (payload.tool_name || '?') + (argsLabel ? '(' + argsLabel + ')' : ''));
        dom.statusNow.innerHTML =
          'Now: <span class="soc-ai-status-now-tool"></span>' + (argsLabel ? ' (' + _esc(argsLabel) + ')' : '');
        const toolEl = dom.statusNow.querySelector('.soc-ai-status-now-tool');
        if (toolEl) toolEl.textContent = payload.tool_name || '';
        _addEvent(kind, payload, {
          text: (payload.tool_name || '?') + (argsLabel ? ' · ' + argsLabel : ''),
        });
        // Bump phase progress as the tool count grows (heuristic — phase
        // completion is unknown until the next phase event).
        const sub = Math.min(0.85, 0.1 + state.toolCount * 0.02);
        _setProgress(state.phase || 'investigator', sub);
        _updateStatusForPhase();
        break;
      }
      case 'tool_result': {
        state.currentTool = null;
        let summary = '';
        const r = payload.result;
        if (r == null) summary = 'null';
        else if (Array.isArray(r)) summary = r.length + ' rows';
        else if (typeof r === 'object') {
          if (r.error) summary = 'error: ' + _short(r.message || r.error, 60);
          else if (Array.isArray(r.items)) summary = r.items.length + ' rows' + (r.truncated ? ' (truncated of ' + r.total + ')' : '');
          else if (typeof r.total === 'number') summary = r.total + ' rows';
          else summary = _short(JSON.stringify(r), 60);
        } else {
          summary = _short(String(r), 60);
        }
        _addEvent(kind, payload, {
          text: (payload.tool_name || '?') + ' → ' + summary,
        });
        break;
      }
      case 'model_response': {
        const content = (payload.content || '').trim();
        const trace = payload.reasoning_trace || null;
        if (content || trace) {
          _addEvent(kind, payload, {
            text: content ? _short(content, 90) : '(thinking)',
            trace: trace,
            icon: trace ? '💭' : '…',
          });
        }
        break;
      }
      case 'investigation_transcript': {
        const ev = payload.evidence || [];
        const oq = payload.open_questions || [];
        _addEvent(kind, payload, {
          text: 'Round ' + (payload.round || '?') + ' transcript · ' +
                ev.length + ' evidence · ' + oq.length + ' gaps',
          trace: payload.tentative_summary || null,
        });
        // Round complete → bump phase to synthesizer.
        state.phase = 'synthesizer';
        if (typeof payload.round === 'number') state.round = payload.round;
        _setProgress('synthesizer', 0.3);
        _updateStatusForPhase();
        break;
      }
      case 'usage': {
        state.requestCount += (payload.requests || 0);
        state.tokensIn += (payload.input_tokens || 0);
        state.tokensOut += (payload.output_tokens || 0);
        state.tokenSeries.push({
          t: Date.now() - state.startTime,
          total: state.tokensIn + state.tokensOut,
        });
        dom.kpiTokens.textContent = _kfmt(state.tokensIn + state.tokensOut);
        _renderSparkline();
        _addEvent(kind, payload, {
          text: (payload.phase || '?') + ' r' + (payload.round || '?') +
                ' · ' + (payload.tool_calls || 0) + ' calls · ' +
                _kfmt((payload.input_tokens || 0) + (payload.output_tokens || 0)) + ' tok',
        });
        break;
      }
      case 'retask': {
        state.phase = 'retask';
        state.round = 2;
        _setProgress('retask', 0.2);
        _updateStatusForPhase();
        _addEvent(kind, payload, {
          text: 'confidence ' + (payload.confidence || 0).toFixed(2) +
                ' below floor ' + (payload.floor || 0).toFixed(2) +
                ' · ' + (payload.open_questions || []).length + ' open Qs',
          trace: (payload.open_questions || []).join('\n'),
        });
        break;
      }
      case 'triage_report': {
        // A triage_report arriving after an error means the synth-first
        // fail-open fallback (round-8) recovered with a structured NMI
        // verdict. Clear the error styling so the panel shows the
        // recovered verdict cleanly instead of a stuck warning.
        if (state.error) {
          state.error = false;
          dom.progressFill.classList.remove('error');
        }
        state.report = payload;
        state.verdictReceived = true;
        _renderVerdict();
        _addEvent(kind, payload, {
          text: (payload.verdict || '?').toUpperCase() +
                ' · conf ' + (payload.confidence || 0).toFixed(2) +
                ' · ' + (payload.recommended_actions || []).length + ' actions',
        });
        // Auto-collapse activity when verdict arrives.
        dom.events.classList.add('collapsed');
        dom.collapseBtn.firstChild.textContent = '▸ ';
        break;
      }
      case 'approval_required': {
        state.pendingApprovals.push({
          token: payload.token,
          tool_name: payload.tool_name,
          tool_args: payload.tool_args,
          rationale: payload.rationale,
        });
        _renderActions();
        _addEvent(kind, payload, {
          text: 'approval needed · ' + (payload.tool_name || '?'),
        });
        break;
      }
      case 'done': {
        state.done = true;
        state.phase = 'done';
        dom.progressFill.classList.add('done');
        dom.progressFill.style.width = '100%';
        _updateStatusForPhase();
        _addEvent(kind, payload, {
          text: 'recommended_count=' + (payload.recommended_count || 0) +
                ' · rounds=' + (payload.rounds || 1),
        });
        if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; }
        break;
      }
      case 'error': {
        state.error = true;
        dom.progressFill.classList.add('error');
        _updateStatusForPhase();
        const head = (payload.phase || '?') + '/r' + (payload.round || 0) +
                     ' · ' + (payload.type || 'Error');
        _addEvent(kind, payload, {
          text: head + ' · ' + _short(payload.message || '', 80),
          trace: payload.hint ? 'hint: ' + payload.hint : null,
          icon: '⚠',
        });
        break;
      }
      default:
        _addEvent(kind, payload, { text: kind, icon: '·' });
    }
  }

  function _esc(s) {
    return String(s).replace(/[&<>"']/g, c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // ---------------------------------------------------------------------------
  // SSE consumer (uses fetch streams since /investigate is POST)
  // ---------------------------------------------------------------------------
  async function startInvestigation(alertId) {
    ensurePanel();
    showPanel();
    resetPanel(alertId);

    const url = getSocAiUrl().replace(/\/$/, '') + '/investigate';
    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream', ...authHeaders() },
        body: JSON.stringify({ alert_id: alertId }),
      });
      if (!resp.ok) {
        handleSseEvent('error', {
          phase: 'transport', round: 0,
          type: 'HTTP' + resp.status,
          message: (await resp.text()).slice(0, 300),
          hint: 'soc-ai endpoint reachable? Cert trusted?',
        });
        return;
      }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let currentEvent = null;
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();
        for (const line of lines) {
          if (line.startsWith('event:')) {
            currentEvent = line.slice(6).trim();
          } else if (line.startsWith('data:')) {
            const data = line.slice(5).trim();
            try {
              const parsed = JSON.parse(data);
              const payload = parsed.payload || parsed;
              handleSseEvent(currentEvent || 'message', payload);
            } catch (e) {
              handleSseEvent('error', {
                phase: 'sse', round: 0, type: 'ParseError',
                message: String(e),
                hint: 'malformed SSE line: ' + _short(data, 120),
              });
            }
            currentEvent = null;
          }
        }
      }
    } catch (e) {
      // A thrown fetch (vs a non-OK response) on first run is almost always
      // the self-signed TLS cert: the browser blocks the cross-origin request
      // before it reaches soc-ai, surfacing as `TypeError: Failed to fetch`
      // (Chrome), `Load failed` (Safari) or `NetworkError` (Firefox). Give an
      // actionable hint with the exact URL to visit instead of a generic
      // "network failure" — this was the #1 first-run dogfooding wall.
      const base = getSocAiUrl().replace(/\/$/, '');
      const looksLikeCert =
        e && e.name === 'TypeError' &&
        /failed to fetch|load failed|networkerror/i.test(String((e && e.message) || e));
      handleSseEvent('error', {
        phase: 'transport', round: 0, type: e.name || 'Error',
        message: String(e),
        hint: looksLikeCert
          ? 'Browser blocked the request — the soc-ai TLS cert is most likely '
            + 'untrusted. Open ' + base + '/healthz in this browser once, accept '
            + 'the self-signed cert, then retry. (If that page loads fine, the '
            + 'cert is trusted and this is a genuine network error.)'
          : 'network/socket failure during SSE stream',
      });
    }
  }

  // ---------------------------------------------------------------------------
  // Button injection
  // ---------------------------------------------------------------------------
  // SO 3.0.0 frontend (Vue + Vuetify) does NOT embed alert ES _ids in the
  // DOM. Each row's <td> cells hold field VALUES in the same column order
  // as the table header. We read the header row to build a column->position
  // map, extract per-row context, then resolve to the real ES _id via the
  // fetch-interception cache (primary) or by clicking expand and reading
  // soc_id from the detail panel (fallback).

  function readColumnMap() {
    // Find the header row in the alerts table. It's a <tr> whose cells are
    // column NAMES (e.g. 'rule.uuid', 'source.ip'). Different from the
    // 'main-row' data rows.
    const allTrs = document.querySelectorAll('tr');
    for (const tr of allTrs) {
      if (tr.classList && tr.classList.contains('main-row')) continue;
      const cells = tr.querySelectorAll('th, td');
      if (cells.length < 4) continue;
      const map = {};
      let nameLikeCount = 0;
      cells.forEach((c, i) => {
        const text = (c.textContent || '').trim();
        if (text && text.length < 40 && /^[a-zA-Z@][a-zA-Z0-9_.]*$|^Timestamp$/.test(text)) {
          map[i] = text;
          nameLikeCount++;
        }
      });
      // Heuristic: a real header has a bunch of dotted field names.
      if (nameLikeCount >= 3) return map;
    }
    return null;
  }

  function extractRowContext(row) {
    const colMap = readColumnMap();
    if (!colMap) return {};
    const cells = row.querySelectorAll('td');
    const ctx = {};
    cells.forEach((c, i) => {
      const colName = colMap[i];
      if (!colName) return;
      const v = (c.textContent || '').trim();
      if (v) ctx[colName] = v;
    });
    return ctx;
  }

  // ---------------------------------------------------------------------------
  // Expand-panel fallback: click expand, read soc_id (= ES _id) from the
  // revealed detail row.
  // ---------------------------------------------------------------------------
  function _findExpandToggle(row) {
    return (
      row.querySelector('button[data-aid="events_item_expand_alerts"]') ||
      row.querySelector('[data-aid="events_item_expand_alerts"]') ||
      row.querySelector('[aria-label*="expand" i]') ||
      null
    );
  }

  function _looksLikeEsId(s) {
    return typeof s === 'string'
      && /^[A-Za-z0-9_-]{15,40}$/.test(s)
      && /[A-Za-z]/.test(s)
      && /[0-9]/.test(s);
  }

  function _readSocIdFromExpandedPanel(row) {
    const candidates = [];
    let node = row.nextElementSibling;
    let hops = 0;
    while (node && hops < 6) {
      if (node.tagName === 'TR' && !node.classList.contains('main-row')) {
        candidates.push(node);
      }
      node = node.nextElementSibling;
      hops++;
    }
    for (const panel of candidates) {
      // Pattern A: a "soc_id" label next to its value.
      const all = panel.querySelectorAll('*');
      for (const el of all) {
        const t = (el.textContent || '').trim();
        if (t === 'soc_id' || t === 'soc_id:') {
          const sib = el.nextElementSibling;
          if (sib) {
            const v = (sib.textContent || '').trim();
            if (_looksLikeEsId(v)) return v;
          }
          const parent = el.parentElement;
          if (parent) {
            for (const e2 of parent.querySelectorAll('*')) {
              const v = (e2.textContent || '').trim();
              if (_looksLikeEsId(v) && v !== t) return v;
            }
          }
        }
      }
      // Pattern B: any standalone _id-shape token.
      for (const c of panel.querySelectorAll('td, span, div')) {
        const t = (c.textContent || '').trim();
        if (_looksLikeEsId(t) && t.length === 20) return t;
      }
    }
    return null;
  }

  function _waitMs(ms) { return new Promise((r) => setTimeout(r, ms)); }

  async function _resolveViaExpand(row) {
    const toggle = _findExpandToggle(row);
    if (!toggle) return null;
    toggle.click();
    for (let i = 0; i < 30; i++) {
      await _waitMs(150);
      const id = _readSocIdFromExpandedPanel(row);
      if (id) {
        try { toggle.click(); } catch (_e) {}
        return id;
      }
    }
    return null;
  }

  async function resolveAlertIdFromRow(row) {
    const ctx = extractRowContext(row);
    console.info('[soc-ai] row context:', ctx);
    // 1) cache hit (populated by the fetch interceptor at document-start).
    const key = _keyFromRowCtx(ctx);
    if (key) {
      const cached = _idCache.get(key);
      if (cached) {
        console.info('[soc-ai] resolved', cached, 'from cache');
        return { id: cached, ctx, found_via: 'cache' };
      }
    }
    console.info('[soc-ai] cache miss (key:', key, '; cache size:', _idCache.size, ') — trying expand panel');
    // 2) expand-panel fallback: click expand, read soc_id.
    try {
      const id = await _resolveViaExpand(row);
      if (id) {
        console.info('[soc-ai] resolved', id, 'from expand-panel');
        return { id, ctx, found_via: 'expand-panel' };
      }
    } catch (e) {
      console.error('[soc-ai] expand-panel resolve failed:', e);
    }
    return { id: null, ctx, found_via: 'unresolved' };
  }

  function injectButtons() {
    // Only inject on SO 3.0.0 data rows (`tr.main-row`). Header rows + group
    // headers don't have actionable per-alert context.
    const rows = document.querySelectorAll('tr.main-row');
    if (rows.length === 0) return;  // not on the alerts page
    rows.forEach((row) => {
      if (row.dataset.socAiAttached) return;
      row.dataset.socAiAttached = '1';
      const btn = document.createElement('button');
      btn.className = 'soc-ai-button hunt';
      btn.textContent = '🔍 Hunt with AI';
      btn.style.cssText =
        'background:linear-gradient(135deg,#2563eb,#7c3aed);color:white;border:none;border-radius:3px;padding:3px 8px;font-size:11px;cursor:pointer;margin-left:6px;font-weight:600;';
      btn.onclick = (ev) => {
        ev.stopPropagation();
        ev.preventDefault();
        // INSTANT visual feedback: open the panel + show "Resolving…" status
        // BEFORE doing any sync work (extractRowContext walks every <tr> in
        // SO's DOM and can take hundreds of ms). The actual resolution is
        // pushed to a setTimeout so the browser paints the panel first.
        btn.textContent = '🔍 …';
        btn.disabled = true;
        ensurePanel();
        showPanel();
        resetPanel('?');
        if (dom.statusPhase) dom.statusPhase.textContent = 'Resolving alert id…';
        if (dom.statusNow) dom.statusNow.textContent = '';

        setTimeout(async () => {
          try {
            const { id, ctx, found_via } = await resolveAlertIdFromRow(row);
            if (id) {
              console.info('[soc-ai] resolved alert', id, 'via', found_via);
              startInvestigation(id);
            } else {
              if (dom.statusPhase) dom.statusPhase.textContent = 'No alert id';
              if (dom.statusIcon) dom.statusIcon.innerHTML = '<span class="soc-ai-x">⚠</span>';
              const hint = ctx['rule.uuid']
                ? `Could not find a matching alert (rule.uuid=${ctx['rule.uuid']}).`
                : 'Could not extract row context.';
              const manual = window.prompt(
                hint + ' Paste an ES _id manually if you have one:',
                ''
              );
              if (manual && manual.trim()) startInvestigation(manual.trim());
            }
          } finally {
            btn.textContent = '🔍 Hunt with AI';
            btn.disabled = false;
          }
        }, 0);
      };
      // Append to the last data cell in the row.
      const cells = row.querySelectorAll('td');
      const lastCell = cells[cells.length - 1];
      if (lastCell) lastCell.appendChild(btn);
    });
  }

  // SO 3.0.0's Vue frontend mutates the DOM aggressively (hundreds of
  // mutations/sec during alert refresh). A naive
  // `new MutationObserver(injectButtons)` calls
  // `document.querySelectorAll('tr.main-row')` on every mutation, which
  // tanks page perf. Coalesce through rAF + a 500ms floor; the user can't
  // see a button that lands 250ms late, and Vue's row recycling means the
  // *same* main-row often gets retargeted dozens of times in quick
  // succession before settling.
  let _injectScheduled = false;
  let _lastInjectAt = 0;
  function _scheduleInject() {
    if (_injectScheduled) return;
    _injectScheduled = true;
    const fire = () => {
      _injectScheduled = false;
      _lastInjectAt = Date.now();
      try { injectButtons(); } catch (e) { console.warn('[soc-ai] inject failed:', e); }
    };
    const sinceLast = Date.now() - _lastInjectAt;
    if (sinceLast < 500) {
      window.setTimeout(() => window.requestAnimationFrame(fire), 500 - sinceLast);
    } else {
      window.requestAnimationFrame(fire);
    }
  }

  function _mutationsAffectAlertTable(mutations) {
    // Cheap filter: only inspect direct tag of added nodes — DON'T descend
    // with querySelector. SO's Vue frontend fires hundreds of mutations per
    // second during alerts list refresh + expand/collapse animations. The
    // querySelector descent we used to do here was the dominant CPU cost
    // during un-expand (3+ seconds frozen). If a row is added inside a
    // subtree we miss this tick, the next tick's mutation on that row
    // directly will catch it.
    for (let i = 0; i < mutations.length; i++) {
      const m = mutations[i];
      const t = m.target;
      if (t && t.id === 'soc-ai-host') continue;
      const added = m.addedNodes;
      const n = added && added.length;
      if (!n) continue;
      for (let j = 0; j < n; j++) {
        const node = added[j];
        if (node.nodeType !== 1) continue;
        const tag = node.tagName;
        if (tag === 'TR' || tag === 'TBODY' || tag === 'TABLE') return true;
      }
    }
    return false;
  }

  // Also add a global launcher button for environments where row injection fails.
  function ensureGlobalButton() {
    if (document.getElementById('soc-ai-launcher')) return;
    const btn = document.createElement('button');
    btn.id = 'soc-ai-launcher';
    btn.textContent = '🔍 soc-ai';
    btn.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:2147483645;background:linear-gradient(135deg,#2563eb,#7c3aed);color:white;border:none;border-radius:24px;padding:10px 16px;font-size:13px;font-weight:600;cursor:pointer;box-shadow:0 4px 12px rgba(0,0,0,.3);';
    btn.onclick = () => {
      const alertId = window.prompt('Alert ID to investigate:', '');
      if (alertId) startInvestigation(alertId.trim());
    };
    document.body.appendChild(btn);
  }

  // ---------------------------------------------------------------------------
  // Boot
  // ---------------------------------------------------------------------------
  function boot() {
    if (!document.body) {
      // Some SPAs swap document.body during boot; retry shortly.
      window.setTimeout(boot, 250);
      return;
    }
    ensureGlobalButton();
    injectButtons();
    const obs = new MutationObserver((mutations) => {
      if (_mutationsAffectAlertTable(mutations)) _scheduleInject();
    });
    obs.observe(document.body, { childList: true, subtree: true });
    // Re-trigger on hash changes (SO 3.0.0 SPA routing).
    window.addEventListener('hashchange', () => {
      console.info('[soc-ai] hashchange:', location.hash);
      _scheduleInject();
    });
    // Periodic backstop: the cheap mutation filter (no querySelector
    // descent) misses cases where Vue inserts a wrapper subtree
    // containing rows. Every 2s, peek for any unattached main-row and
    // schedule an inject if found. The query short-circuits at the first
    // hit, so this is sub-millisecond when nothing's pending.
    window.setInterval(() => {
      if (document.querySelector('tr.main-row:not([data-soc-ai-attached])')) {
        _scheduleInject();
      }
    }, 2000);

    // Tampermonkey menu: set the server URL + the API token (v0.8.0).
    if (typeof GM_registerMenuCommand === 'function') {
      GM_registerMenuCommand('soc-ai: set API token', () => {
        const t = window.prompt(
          'soc-ai API token (Bearer scai_…). Mint one in the soc-ai config '
          + 'console → API Tokens. Leave blank to clear:',
          getSocAiToken());
        if (t !== null) {
          setSocAiToken(t.trim());
          window.alert('soc-ai API token ' + (t.trim() ? 'saved.' : 'cleared.'));
        }
      });
      GM_registerMenuCommand('soc-ai: set server URL', () => {
        const u = window.prompt('soc-ai server URL:', getSocAiUrl());
        if (u && u.trim()) { setSocAiUrl(u.trim()); window.alert('soc-ai URL saved: ' + u.trim()); }
      });
    }
    console.info('[soc-ai] booted; soc_ai_url =', getSocAiUrl(), '· token =',
                 getSocAiToken() ? 'set' : 'none');
  }
  boot();
})();
