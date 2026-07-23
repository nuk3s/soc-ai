import { ChevronRight, Key, ShieldAlert, Users } from 'lucide-react';
import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { ApplyBadge, SourceBadge } from '../components/Badges';
import { NumberField, Select, Toggle } from '../components/Controls';
import { ManagedList } from '../components/ManagedList';
import { SectionTitle } from '../components/Panel';
import { ErrorState, LoadingState, Spinner } from '../components/States';
import { AgentToolsPanel } from './AgentToolsPanel';
import { ApiKeysPanel } from './ApiKeysPanel';
import { DataSourcesPanel } from './DataSourcesPanel';
import { EgressPolicyPanel } from './EgressPolicyPanel';
import { NotificationsPanel } from './NotificationsPanel';
import { RedactionPreviewPanel } from './RedactionPreviewPanel';
import { DetectionTuningPanel } from './DetectionTuningPanel';
import { MaintenancePanel } from './MaintenancePanel';
import { RunbooksPanel } from './RunbooksPanel';
import { addInternalIdentifier, createUser, dismissIdentifier, getConfig, getDiscoveryScan, getGatewayModels, getInternalIdentifiers, getModelFitness, listDangerSettings, listUsers, mintToken, reembedRunbooks, removeIdentifier, resetUserPassword, revokeToken, saveDangerSetting, setIdentifierActive, setSetting, setUserRole, startDiscoveryScan, testConnection, toggleUserDisabled } from '../lib/api';
import type { IdentifierKind, InternalIdentifiers, ModelFitness, RagReembedResult } from '../lib/api';
import { demoBlocked, useDemo } from '../lib/demo';
import { useAsync } from '../lib/useAsync';
import type { AdminUser, ConnTestResult, DangerSetting, Setting, SettingGroup } from '../lib/types';
import { ConfigNav } from './ConfigNav';

/** Slugify a section title into a stable DOM id / anchor fragment. */
function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
}

/** Nearest scrollable ancestor (the AppShell's overflow-y-auto content pane). */
function scrollContainerOf(el: HTMLElement): HTMLElement | null {
  for (let p = el.parentElement; p; p = p.parentElement) {
    const oy = getComputedStyle(p).overflowY;
    if (oy === 'auto' || oy === 'scroll') return p;
  }
  return null;
}

// ── Config-page information architecture ─────────────────────────────────────
// Top-level parent headers, in display order. The server-driven settings groups
// carry their parent in GET /config (SECTION_PARENTS in
// soc_ai/store/config_overrides.py — the single source of truth for THEIR
// grouping); the frontend-owned standalone panels declare theirs in PANELS
// below. A parent the frontend doesn't know yet is appended after these.
const PARENT_ORDER = [
  'Models & Reasoning',
  'Triage & Workflow',
  'Retrieval & Memory',
  'Privacy & Egress',
  'Data & Enrichment',
  'System',
];

// Standalone (frontend-owned) sections: stable DOM id (deep-link anchor — these
// ids predate the grouped nav and MUST NOT change), label (doubles as the
// `collapsed`-map key), parent header, and placement relative to the parent's
// server-driven groups: after a specific group title, at the start, or
// (default) appended at the end of the parent.
interface PanelDef {
  id: string;
  label: string;
  parent: string;
  placement?: { afterGroup?: string; at?: 'start' };
}
const PANELS: PanelDef[] = [
  { id: 'agent-tools', label: 'Agent tools', parent: 'Models & Reasoning' },
  { id: 'notifications-webhook', label: 'Notification webhook', parent: 'Triage & Workflow', placement: { afterGroup: 'Notifications' } },
  { id: 'runbooks', label: 'Runbooks', parent: 'Retrieval & Memory' },
  { id: 'egress-policy', label: 'Egress policy', parent: 'Privacy & Egress', placement: { at: 'start' } },
  { id: 'internal-identifiers', label: 'Internal identifiers', parent: 'Privacy & Egress', placement: { afterGroup: 'Discovery' } },
  { id: 'redaction-preview', label: 'Redaction preview', parent: 'Privacy & Egress' },
  { id: 'data-sources', label: 'Data sources', parent: 'Data & Enrichment', placement: { at: 'start' } },
  { id: 'detection-tuning', label: 'Detection tuning', parent: 'Data & Enrichment' },
  { id: 'api-keys', label: 'API keys', parent: 'Data & Enrichment' },
  { id: 'users', label: 'Users', parent: 'System' },
  { id: 'api-tokens', label: 'API tokens', parent: 'System' },
  { id: 'maintenance', label: 'Scheduled maintenance', parent: 'System' },
  { id: 'diagnostics', label: 'Diagnostics', parent: 'System' },
  { id: 'danger-zone', label: 'Danger Zone', parent: 'System' },
];

// Ids the group-id generator must never produce: every standalone panel id plus
// in-page anchors that aren't nav sections.
const RESERVED_IDS: ReadonlySet<string> = new Set([...PANELS.map((p) => p.id), 'rag-reembed']);

type ConfigChild =
  | { kind: 'group'; id: string; label: string; group: SettingGroup }
  | { kind: 'panel'; id: string; label: string };

interface ConfigParent {
  label: string;
  children: ConfigChild[];
}

// The Retrieval (RAG) model settings — rendered as gateway-fed dropdowns (same
// list as the analyst model) instead of free text. Empty string = tier off.
const RAG_MODEL_KEYS = new Set(['rag_embed_model', 'rag_rerank_model']);
// Sentinel for the dropdowns' "Other…" escape hatch (reveals a free-text input
// for a custom model id the gateway doesn't list). Never a real model id.
const OTHER_MODEL_OPTION = '__other__';

/**
 * Collapsible section shell — the same chevron + toggle header the settings-group
 * map uses, factored out so every standalone section on the Config page folds the
 * same way. `title` doubles as the stable key into the parent `collapsed` map.
 */
function CollapsibleConfigSection({
  id,
  title,
  right,
  collapsed,
  onToggle,
  className,
  children,
}: {
  id: string;
  title: ReactNode;
  right?: ReactNode;
  collapsed: boolean;
  onToggle: () => void;
  className?: string;
  children: ReactNode;
}) {
  // The clickable toggle is the title + chevron; any interactive `right` content
  // (a Scan-now / Mint-token button) sits OUTSIDE the toggle button so we never
  // nest a <button> inside a <button> (invalid HTML).
  return (
    <div id={id} className={className ?? 'mb-[22px] scroll-mt-6'}>
      <SectionTitle
        right={
          <>
            {right}
            <button
              type="button"
              onClick={onToggle}
              aria-expanded={!collapsed}
              aria-label={collapsed ? 'Expand section' : 'Collapse section'}
              className="group flex-none text-faint hover:text-text-2"
            >
              <ChevronRight
                size={15}
                className="transition-transform"
                style={{ transform: collapsed ? 'none' : 'rotate(90deg)' }}
              />
            </button>
          </>
        }
      >
        <button type="button" onClick={onToggle} className="text-left">
          {title}
        </button>
      </SectionTitle>
      {!collapsed && children}
    </div>
  );
}

// Grade chip + "Check fitness" button shown beside the analyst-model control.
// green=pass / amber=degraded / red=fail. Fail-soft: with no grade yet (or after a
// probe error) it shows only the button, never an error — the check is advisory
// and NEVER blocks Apply.
const _FITNESS_STYLE: Record<string, { bg: string; fg: string; label: string }> = {
  pass: { bg: '#12b76a22', fg: '#12b76a', label: 'fit' },
  degraded: { bg: '#f79f0022', fg: '#f79009', label: 'degraded' },
  fail: { bg: '#f0443822', fg: '#f04438', label: 'unfit' },
};

function ModelFitnessChip({
  fitness,
  loading,
  onCheck,
}: {
  fitness: ModelFitness | null;
  loading: boolean;
  onCheck: () => void;
}) {
  const style = fitness ? _FITNESS_STYLE[fitness.grade] : undefined;
  return (
    <div className="flex items-center gap-2">
      {loading && <span className="text-[11px] text-faint">Checking fitness…</span>}
      {!loading && fitness && style && (
        <span
          className="rounded px-1.5 py-0.5 text-[10.5px] font-semibold uppercase tracking-wide"
          style={{ background: style.bg, color: style.fg }}
          title={fitness.detail}
        >
          {style.label}
        </span>
      )}
      {!loading && fitness && style && (
        <span className="max-w-[190px] truncate text-[11px] text-dim" title={fitness.detail}>
          {fitness.detail}
        </span>
      )}
      <button
        type="button"
        className="rounded border border-border bg-surface-2 px-2 py-0.5 text-[11px] font-medium hover:bg-surface-3 transition-colors disabled:opacity-50"
        onClick={onCheck}
        disabled={loading}
      >
        Check fitness
      </button>
    </div>
  );
}

export function Config() {
  const demo = useDemo(); // read-only demo: config writes show a note, never POST
  const [nonce, setNonce] = useState(0);
  // Collapsed config sections (the panel is long — let the operator fold away
  // the groups they aren't tuning). Session-scoped; deep-link auto-expands.
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const toggleSection = (title: string) =>
    setCollapsed((c) => ({ ...c, [title]: !c[title] }));
  const { data, loading, error } = useAsync(getConfig, [nonce]);

  // Fetch users in sync with nonce
  useEffect(() => {
    listUsers()
      .then((r) => setUsers(r.users))
      .catch((e: unknown) => setUserError(e instanceof Error ? e.message : 'Failed to load users'));
  }, [nonce]);

  useEffect(() => {
    let active = true;
    setDangerLoading(true);
    setDangerError('');
    listDangerSettings()
      .then((r) => { if (active) setDangerSettings(r); })
      .catch(() => { if (active) setDangerError('Danger Zone unavailable (admin only).'); })
      .finally(() => { if (active) setDangerLoading(false); });
    return () => { active = false; };
  }, []);

  // Models the LiteLLM gateway serves — upgrades the analyst-model field from
  // free text to a dropdown. Fetched separately from /config so a slow or down
  // gateway never delays the page; on failure the free-text field remains.
  const [gatewayModels, setGatewayModels] = useState<string[]>([]);
  useEffect(() => {
    let active = true;
    getGatewayModels()
      .then((r) => { if (active && r.ok) setGatewayModels(r.models); })
      .catch(() => {});
    return () => { active = false; };
  }, [nonce]);

  // Which RAG-model dropdowns are in "Other…" mode (free-text custom-id input
  // revealed under the select). Keyed by setting key; reset on Discard.
  const [ragCustomModel, setRagCustomModel] = useState<Record<string, boolean>>({});

  // ── Staged settings edits (explicit save/apply) ────────────────────────────
  // Controls no longer persist on change. Instead each edit is STAGED here as a
  // string keyed by setting key (matching setSetting's value type). Controls read
  // the staged value when present, else the server value. A sticky "Apply
  // changes (N)" bar persists all staged edits at once; "Discard" drops them.
  // This removes the "did that save?" ambiguity of the old per-field auto-save.
  const [staged, setStaged] = useState<Record<string, string>>({});
  // Bumped on discard/apply to force uncontrolled inputs (NumberField/text, which
  // use defaultValue) to remount and re-read the current server/staged value.
  const [formNonce, setFormNonce] = useState(0);
  const [applying, setApplying] = useState(false);
  // Per-key apply errors, surfaced inline beside the offending control.
  const [applyErrors, setApplyErrors] = useState<Record<string, string>>({});
  // Sticky-bar result after an Apply: how many saved, and whether any need a restart.
  const [applyResult, setApplyResult] = useState<{ ok: boolean; msg: string } | null>(null);

  // ── Analyst-model fitness (E1.1) ───────────────────────────────────────────
  // A model that LISTS on the gateway can still be unfit (all-fallback verdicts).
  // We grade it: on the analyst-model dropdown changing (or a manual "Check
  // fitness"), fire the probe and show the grade inline. Strictly non-blocking —
  // it NEVER gates Apply; a fetch error shows nothing (neutral), never an error.
  const [fitness, setFitness] = useState<ModelFitness | null>(null);
  const [fitnessLoading, setFitnessLoading] = useState(false);
  // The analyst model currently selected (staged edit wins over the server value).
  const currentAnalystModel =
    staged['analyst_model'] ??
    data?.groups.flatMap((g) => g.items).find((i) => i.key === 'analyst_model')?.value ??
    '';

  const runFitness = () => {
    setFitnessLoading(true);
    getModelFitness()
      .then((r) => setFitness(r))
      // Fail-soft: a probe/gateway/permission error must not surface as an error
      // chip — clear the stale grade and stay neutral.
      .catch(() => setFitness(null))
      .finally(() => setFitnessLoading(false));
  };

  // Auto-run (debounced) whenever the selected analyst model changes. The grade
  // is model-specific, so a stale grade for the previous model would mislead —
  // clear it immediately, then re-probe after a short settle so rapid dropdown
  // changes don't spam the gateway.
  useEffect(() => {
    if (!currentAnalystModel) return;
    setFitness(null);
    const t = setTimeout(() => {
      let cancelled = false;
      setFitnessLoading(true);
      getModelFitness()
        .then((r) => { if (!cancelled) setFitness(r); })
        .catch(() => { if (!cancelled) setFitness(null); })
        .finally(() => { if (!cancelled) setFitnessLoading(false); });
      return () => { cancelled = true; };
    }, 600);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentAnalystModel]);

  const dirtyKeys = Object.keys(staged);
  const isDirty = dirtyKeys.length > 0;

  const [minted, setMinted] = useState('');
  // The API-tokens section has no error strip of its own; this carries the demo
  // note (mint/revoke are blocked in the read-only demo) via the section's own
  // inline status element rather than a new toast.
  const [tokenMsg, setTokenMsg] = useState('');

  // Auto-dismiss the freshly-minted token banner so the secret doesn't linger
  // on screen until reload. It still carries a manual ✕ for immediate dismissal.
  useEffect(() => {
    if (!minted) return;
    const t = setTimeout(() => setMinted(''), 30000);
    return () => clearTimeout(t);
  }, [minted]);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [userError, setUserError] = useState('');
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'analyst' });
  const [resetPw, setResetPw] = useState<{ id: number; password: string } | null>(null);

  // Auto-dismiss the plaintext reset-password banner, same as the mint-token
  // banner above — so the secret doesn't linger on an unattended screen. Still
  // carries a manual ✕ for immediate dismissal.
  useEffect(() => {
    if (!resetPw) return;
    const t = setTimeout(() => setResetPw(null), 30000);
    return () => clearTimeout(t);
  }, [resetPw]);

  // Danger-zone state
  const [dangerSettings, setDangerSettings] = useState<DangerSetting[]>([]);
  const [dangerLoading, setDangerLoading] = useState(false);
  const [dangerError, setDangerError] = useState('');
  const [dangerEditKey, setDangerEditKey] = useState<string | null>(null);
  const [dangerEditValue, setDangerEditValue] = useState('');
  const [dangerConfirm, setDangerConfirm] = useState('');
  const [dangerSaving, setDangerSaving] = useState(false);
  const [dangerSaveMsg, setDangerSaveMsg] = useState<{ key: string; msg: string; ok: boolean } | null>(null);
  const [connTestResults, setConnTestResults] = useState<Record<string, ConnTestResult & { loading?: boolean }>>({});

  // ── Runbook re-embed (E4.1) ────────────────────────────────────────────────
  // One admin action for the opt-in semantic tier: embed every runbook whose
  // vector is missing (gateway was down during a save) or stale (the embed
  // model id changed). Counts are shown verbatim — honest, incl. failures.
  const [reembedding, setReembedding] = useState(false);
  const [reembedResult, setReembedResult] = useState<RagReembedResult | null>(null);
  const [reembedError, setReembedError] = useState('');
  const runReembed = () => {
    const blocked = demoBlocked(demo);
    if (blocked) { setReembedError(blocked); return; } // demo: no doomed write
    setReembedding(true);
    setReembedResult(null);
    setReembedError('');
    reembedRunbooks()
      .then((r) => setReembedResult(r))
      .catch((e: unknown) =>
        setReembedError(e instanceof Error ? e.message : 'Re-embed failed'),
      )
      .finally(() => setReembedding(false));
  };

  // Internal-identifier managed list (separate nonce so its mutations refetch
  // independently of the settings/users blocks above).
  const [identNonce, setIdentNonce] = useState(0);
  const [idents, setIdents] = useState<InternalIdentifiers | null>(null);
  const [identError, setIdentError] = useState('');
  const [scanning, setScanning] = useState(false);
  useEffect(() => {
    let active = true;
    getInternalIdentifiers()
      .then((r) => { if (active) { setIdents(r); setIdentError(''); } })
      .catch((e: unknown) => { if (active) setIdentError(e instanceof Error ? e.message : 'Failed to load identifiers'); });
    return () => { active = false; };
  }, [identNonce]);

  const refetchIdents = () => setIdentNonce((n) => n + 1);

  // ── Left-nav / page section model ──────────────────────────────────────────
  // Two-level: PARENT_ORDER headers, each holding the server-driven settings
  // groups whose `parent` (from GET /config) matches, with the frontend-owned
  // standalone panels spliced in per their PANELS placement. Nav order ==
  // render order == DOM order by construction (both come from this structure).
  const layout = useMemo<ConfigParent[]>(() => {
    // Collision-proof group ids: slugs are deduped against the reserved panel
    // ids AND each other, so a future server section titled e.g. "Users" can
    // never produce a duplicate DOM id (which would make anchor clicks resolve
    // to the wrong section). Current titles slug cleanly, so the historical
    // anchors (#agent, #retrieval-rag, …) are unchanged.
    const used = new Set(RESERVED_IDS);
    const idFor = (title: string) => {
      const base = slug(title) || 'section';
      let id = base;
      for (let n = 2; used.has(id); n++) id = `${base}-${n}`;
      used.add(id);
      return id;
    };
    const parentOrder = [...PARENT_ORDER];
    const byParent = new Map<string, ConfigChild[]>();
    const bucket = (parent: string) => {
      let children = byParent.get(parent);
      if (!children) {
        children = [];
        byParent.set(parent, children);
        if (!parentOrder.includes(parent)) parentOrder.push(parent);
      }
      return children;
    };
    for (const g of data?.groups ?? []) {
      bucket(g.parent ?? g.title).push({ kind: 'group', id: idFor(g.title), label: g.title, group: g });
    }
    for (const p of PANELS) {
      const children = bucket(p.parent);
      const child: ConfigChild = { kind: 'panel', id: p.id, label: p.label };
      const after = p.placement?.afterGroup;
      if (p.placement?.at === 'start') {
        children.unshift(child);
      } else if (after) {
        const i = children.findIndex((c) => c.kind === 'group' && c.label === after);
        children.splice(i === -1 ? children.length : i + 1, 0, child);
      } else {
        children.push(child);
      }
    }
    return parentOrder
      .filter((label) => byParent.has(label))
      .map((label) => ({ label, children: byParent.get(label) ?? [] }));
  }, [data?.groups]);

  // Flat section list in DOM order — drives the scroll-spy and collapse lookup.
  const flatSections = useMemo(() => layout.flatMap((p) => p.children), [layout]);

  // ── Active-section highlight (deterministic scroll-spy) ────────────────────
  // The previous IntersectionObserver version misattributed nav clicks: it
  // derived the active id from only the threshold-crossing entries and took the
  // topmost intersecting one, while scrollIntoView's landing position leaves the
  // PREVIOUS section's tail 2px inside the scrollport (24px scroll-margin vs the
  // 22px inter-section gap) — so clicking "Retrieval (RAG)" highlighted "Online
  // enrichment". Instead: the active section is the LAST one whose top edge has
  // crossed an activation line just under the scrollport top. Exactly one
  // winner, immune to the previous section's sliver, correct for short sections.
  const [activeId, setActiveId] = useState('');
  // Nav clicks / deep-links pin the highlight to the user's intent and hold the
  // spy off until the programmatic jump's scroll events have flushed.
  const spyHoldUntil = useRef(0);
  useEffect(() => {
    if (!flatSections.length) return;
    let raf = 0;
    const compute = () => {
      raf = 0;
      if (performance.now() < spyHoldUntil.current) return;
      const els = flatSections
        .map((s) => document.getElementById(s.id))
        .filter((el): el is HTMLElement => el != null);
      if (!els.length) return;
      const sc = scrollContainerOf(els[0]);
      // 30px = the 24px scroll-margin anchors land at, plus slack.
      const line = (sc ? sc.getBoundingClientRect().top : 0) + 30;
      let current = els[0].id;
      for (const el of els) {
        if (el.getBoundingClientRect().top <= line) current = el.id;
      }
      // Pinned to the bottom → the last section is the destination even though
      // it may be too short to ever reach the activation line.
      if (sc && Math.ceil(sc.scrollTop + sc.clientHeight) >= sc.scrollHeight - 2) {
        current = els[els.length - 1].id;
      }
      setActiveId(current);
    };
    const schedule = () => {
      if (!raf) raf = requestAnimationFrame(compute);
    };
    // Capture-phase listener: the page scrolls inside the AppShell's
    // overflow-y-auto pane, whose scroll events don't bubble to window.
    document.addEventListener('scroll', schedule, true);
    window.addEventListener('resize', schedule);
    schedule();
    return () => {
      document.removeEventListener('scroll', schedule, true);
      window.removeEventListener('resize', schedule);
      if (raf) cancelAnimationFrame(raf);
    };
  }, [flatSections, nonce, identNonce]);

  // Nav click / deep-link entry: force-expand a collapsed target so the anchor
  // is never hidden behind a folded header (the `collapsed` map is keyed by the
  // section label — for groups that's the group title), pin the highlight, and
  // hold the scroll-spy briefly (see above).
  const navigateToSection = (id: string) => {
    const label = flatSections.find((s) => s.id === id)?.label;
    if (label) setCollapsed((c) => ({ ...c, [label]: false }));
    setActiveId(id);
    spyHoldUntil.current = performance.now() + 400;
  };

  // Deep-link support: when arriving at /config#<section> (e.g. the dashboard's
  // "Manage data sources" link → #data-sources), scroll that section into view
  // once its DOM has mounted. Runs after the settings + standalone panels render.
  useEffect(() => {
    if (loading || !data) return;
    const id = window.location.hash.replace('#', '');
    if (!id) return;
    navigateToSection(id);
    const t = setTimeout(() => {
      // Instant snap ('auto', not 'smooth') — smooth-scrolling this long page
      // is slow/choppy; same treatment as the ConfigNav click handler.
      document.getElementById(id)?.scrollIntoView({ behavior: 'auto', block: 'start' });
    }, 60);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loading, data, flatSections]);

  // Wrap a mutation so any error surfaces inline and the list refetches on success.
  // Takes a THUNK, not a live promise: in demo we must decide BEFORE the request
  // is created, so the request is never fired (add/remove/toggle/dismiss).
  const identMutation = (makeP: () => Promise<unknown>) => {
    const blocked = demoBlocked(demo);
    if (blocked) { setIdentError(blocked); return; } // demo: no doomed write
    setIdentError('');
    makeP().then(refetchIdents).catch((e: unknown) =>
      setIdentError(e instanceof Error ? e.message : 'Action failed'),
    );
  };

  const runScanNow = async () => {
    const blocked = demoBlocked(demo);
    if (blocked) { setIdentError(blocked); return; } // demo: no doomed write
    setIdentError('');
    setScanning(true);
    try {
      const start = await startDiscoveryScan();
      if (start.note === 'discovery disabled') {
        setIdentError('Discovery is disabled — enable it in settings to scan.');
        setScanning(false);
        return;
      }
      // Poll until the scan is no longer running, then refetch the list. A bounded
      // number of polls (≈2 min at 1.5s each) keeps a wedged scan from spinning the
      // button forever — we surface a timeout instead of staying disabled.
      let running = start.running;
      for (let i = 0; running && i < 80; i++) {
        await new Promise((r) => setTimeout(r, 1500));
        running = (await getDiscoveryScan()).running;
      }
      if (running) {
        setIdentError('Scan is taking longer than expected — check back shortly.');
      }
    } catch (e: unknown) {
      setIdentError(e instanceof Error ? e.message : 'Scan failed');
    } finally {
      setScanning(false);
      refetchIdents();
    }
  };

  // Current value of a setting, honouring any staged (unapplied) edit. Used for
  // dependent-field logic (e.g. the auto-ack threshold enable + the #7 warning).
  const stagedBool = (key: string, fallback: boolean) =>
    staged[key] !== undefined ? staged[key] === 'true' : fallback;
  const stagedStr = (key: string, fallback: string) =>
    staged[key] !== undefined ? staged[key] : fallback;

  const findSetting = (key: string): Setting | undefined =>
    data?.groups.flatMap((g) => g.items).find((i) => i.key === key);

  // Derived: current value of the auto-ack toggle (staged edit takes precedence).
  const autoAckEnabled = (s: Setting | undefined) => {
    if (!s) return false;
    return stagedBool('auto_ack_fp_enabled', s.value as boolean);
  };

  if (loading) return <div className="p-6"><LoadingState label="Loading settings…" /></div>;
  if (error) return <div className="p-6"><ErrorState error={error} /></div>;
  if (!data) return null;

  const toggleValue = (s: Setting) => stagedBool(s.key, s.value as boolean);

  // Stage an edit locally (does NOT persist — Apply does that). Records the value
  // as a string; clears back to "not staged" when it matches the server value so
  // a no-op round-trip doesn't leave the form spuriously dirty.
  const stage = (key: string, value: string, serverValue: string) => {
    setApplyResult(null);
    setApplyErrors((e) => {
      if (!(key in e)) return e;
      const next = { ...e };
      delete next[key];
      return next;
    });
    setStaged((s) => {
      const next = { ...s };
      if (value === serverValue) delete next[key];
      else next[key] = value;
      return next;
    });
  };

  const discardStaged = () => {
    setStaged({});
    setApplyErrors({});
    setApplyResult(null);
    setRagCustomModel({}); // drop "Other…" modes so the selects re-show server values
    setFormNonce((n) => n + 1); // remount uncontrolled inputs so they reset
  };

  // Persist every staged edit. Each failure is surfaced inline on its control and
  // that key stays staged; successful keys clear. Restart-required notes bubble up
  // to the sticky bar. On full success we refetch the config to re-sync sources.
  const applyStaged = async () => {
    const entries = Object.entries(staged);
    if (!entries.length) return;
    const blocked = demoBlocked(demo);
    if (blocked) { setApplyResult({ ok: false, msg: blocked }); return; } // demo: no doomed write
    setApplying(true);
    setApplyErrors({});
    setApplyResult(null);
    const errors: Record<string, string> = {};
    let restartRequired = false;
    let saved = 0;
    const savedKeys: string[] = [];
    const results = await Promise.allSettled(
      entries.map(([key, value]) => setSetting(key, value)),
    );
    results.forEach((r, i) => {
      const key = entries[i][0];
      if (r.status === 'fulfilled') {
        saved += 1;
        savedKeys.push(key);
        if (r.value.restart_required) restartRequired = true;
      } else {
        const reason = r.reason;
        errors[key] = reason instanceof Error ? reason.message : String(reason);
      }
    });
    setApplyErrors(errors);
    setStaged((s) => {
      const next = { ...s };
      for (const key of savedKeys) delete next[key];
      return next;
    });
    const failed = Object.keys(errors).length;
    if (failed === 0) {
      setApplyResult({
        ok: true,
        msg: restartRequired
          ? `Applied ${saved} change${saved === 1 ? '' : 's'} — service restart required for some to take effect`
          : `Applied ${saved} change${saved === 1 ? '' : 's'}`,
      });
      setFormNonce((n) => n + 1);
      setNonce((n) => n + 1); // refetch config → re-sync source badges / values
    } else {
      setApplyResult({
        ok: false,
        msg: `${saved} applied, ${failed} failed — see the highlighted field${failed === 1 ? '' : 's'}`,
      });
    }
    setApplying(false);
  };

  const renderControl = (s: Setting) => {
    const serverStr = String(s.value);
    const err = applyErrors[s.key];
    let control: ReactNode;
    if (s.type === 'toggle') {
      control = (
        <Toggle
          on={toggleValue(s)}
          onChange={(next) => stage(s.key, String(next), serverStr)}
          label={s.key}
        />
      );
    } else if (s.type === 'number') {
      // The auto-ack threshold is only meaningful when the toggle is on.
      const isAutoAckThreshold = s.key === 'auto_ack_fp_threshold';
      const thresholdEnabled = !isAutoAckThreshold || autoAckEnabled(findSetting('auto_ack_fp_enabled'));
      const current = Number(stagedStr(s.key, serverStr));
      control = (
        <div
          aria-disabled={isAutoAckThreshold && !thresholdEnabled}
          style={isAutoAckThreshold && !thresholdEnabled ? { opacity: 0.4, pointerEvents: 'none' } : undefined}
        >
          <NumberField
            key={`${s.key}-${formNonce}`}
            value={current}
            bounds={s.bounds}
            onChange={(v) => stage(s.key, String(v), serverStr)}
          />
          {isAutoAckThreshold && !thresholdEnabled && (
            <div className="text-[11px] text-faint mt-1">Applies when auto-acknowledge is on</div>
          )}
        </div>
      );
    } else if (s.type === 'select') {
      control = (
        <Select
          value={stagedStr(s.key, serverStr)}
          options={s.options}
          onChange={(v) => stage(s.key, v, serverStr)}
        />
      );
    } else if (s.key === 'notify_format') {
      // Fixed-option webhook body shape — render a select over the three formats
      // instead of a free-text field (the backend validates it to json|slack|matrix).
      control = (
        <Select
          value={stagedStr(s.key, serverStr)}
          options={['json', 'slack', 'matrix']}
          onChange={(v) => stage(s.key, v, serverStr)}
        />
      );
    } else if (s.key === 'analyst_model' && gatewayModels.length > 0) {
      // The gateway told us what it serves — offer exactly that list instead of a
      // blind free-text field. The current value stays selectable even if the
      // gateway no longer lists it (so loading the page never mutates config).
      const current = stagedStr(s.key, serverStr);
      const options = gatewayModels.includes(current)
        ? gatewayModels
        : [current, ...gatewayModels];
      control = (
        <div className="flex flex-col items-end gap-1.5">
          <Select
            value={current}
            options={options}
            onChange={(v) => stage(s.key, v, serverStr)}
          />
          <ModelFitnessChip
            fitness={fitness}
            loading={fitnessLoading}
            onCheck={runFitness}
          />
        </div>
      );
    } else if (RAG_MODEL_KEYS.has(s.key) && gatewayModels.length > 0) {
      // RAG model pickers — the analyst-model dropdown pattern (the gateway told
      // us what it serves) with two extras: "(off)" (empty string = the tier's
      // documented OFF semantics) and "Other…" (a free-text input for a custom
      // id — /v1/models can't distinguish embed/rerank/chat models, so ALL served
      // ids are listed rather than filtered). The current value stays selectable
      // even if the gateway no longer lists it (loading the page never mutates
      // config). Falls through to plain free text when the gateway list is empty.
      const current = stagedStr(s.key, serverStr);
      const custom = !!ragCustomModel[s.key];
      const options = [
        { value: '', label: '(off)' },
        ...(current !== '' && !custom && !gatewayModels.includes(current) ? [current] : []),
        ...gatewayModels,
        { value: OTHER_MODEL_OPTION, label: 'Other…' },
      ];
      control = (
        <div className="flex flex-col items-end gap-1.5">
          <Select
            value={custom ? OTHER_MODEL_OPTION : current}
            options={options}
            onChange={(v) => {
              if (v === OTHER_MODEL_OPTION) {
                setRagCustomModel((m) => ({ ...m, [s.key]: true }));
                return; // nothing staged yet — the input below stages the id
              }
              setRagCustomModel((m) => ({ ...m, [s.key]: false }));
              stage(s.key, v, serverStr);
            }}
          />
          {custom && (
            <input
              key={`${s.key}-other-${formNonce}`}
              defaultValue={current}
              placeholder="custom model id"
              onChange={(e) => stage(s.key, e.target.value, serverStr)}
              className="w-[200px] rounded-control border border-border-input bg-bg px-3 py-1.5 font-mono text-[12.5px] text-text outline-none focus:border-accent"
            />
          )}
        </div>
      );
    } else if (s.key === 'analyst_model') {
      // No gateway list (gateway down / empty) — keep the free-text field, but
      // still offer the fitness check on whatever id is typed.
      control = (
        <div className="flex flex-col items-end gap-1.5">
          <input
            key={`${s.key}-${formNonce}`}
            defaultValue={stagedStr(s.key, serverStr)}
            onChange={(e) => stage(s.key, e.target.value, serverStr)}
            className="w-[200px] rounded-control border border-border-input bg-bg px-3 py-1.5 font-mono text-[12.5px] text-text outline-none focus:border-accent"
          />
          <ModelFitnessChip
            fitness={fitness}
            loading={fitnessLoading}
            onCheck={runFitness}
          />
        </div>
      );
    } else {
      control = (
        <input
          key={`${s.key}-${formNonce}`}
          defaultValue={stagedStr(s.key, serverStr)}
          onChange={(e) => stage(s.key, e.target.value, serverStr)}
          className="w-[200px] rounded-control border border-border-input bg-bg px-3 py-1.5 font-mono text-[12.5px] text-text outline-none focus:border-accent"
        />
      );
    }
    return (
      <div className="flex flex-col items-end gap-1">
        {control}
        {err && <span className="max-w-[220px] text-right text-[11px] text-danger">{err}</span>}
      </div>
    );
  };

  // ── #7 Auto-ack coupling: does the current (staged) config actually let
  // auto-ack do anything? Auto-ack only acks FPs that get INVESTIGATED, so it is
  // inert unless auto-triage runs, and its severity floor is medium/low (high/
  // critical are never auto-acked). Detect the inert case to escalate the note to
  // a warning. Sibling settings may live in the DB config; fall back gracefully.
  const autoAckToggle = findSetting('auto_ack_fp_enabled');
  const autoAckOn = autoAckToggle ? autoAckEnabled(autoAckToggle) : false;
  const scheduleSetting = findSetting('auto_triage_schedule_enabled');
  const scheduleOn = scheduleSetting
    ? stagedBool('auto_triage_schedule_enabled', scheduleSetting.value as boolean)
    : undefined;
  const minSevSetting = findSetting('auto_triage_min_severity');
  const minSev = minSevSetting
    ? stagedStr('auto_triage_min_severity', String(minSevSetting.value))
    : undefined;
  const floorTooHigh = minSev === 'high' || minSev === 'critical';
  // Warn only when we can positively see a coupling problem: scheduled auto-triage
  // is off, or the severity floor excludes everything auto-ack could ever clear.
  const autoAckInert = autoAckOn && (scheduleOn === false || floorTooHigh);

  const handleDangerSave = async (key: string) => {
    if (dangerConfirm !== key) return;
    const blocked = demoBlocked(demo);
    if (blocked) { setDangerSaveMsg({ key, msg: blocked, ok: false }); return; } // demo: no doomed write
    setDangerSaving(true);
    setDangerSaveMsg(null);
    try {
      const res = await saveDangerSetting(key, dangerEditValue, dangerConfirm);
      setDangerSaveMsg({
        key,
        msg: res.restart_required ? 'Saved — restart required to apply' : 'Saved and applied',
        ok: true,
      });
      setDangerEditKey(null);
      setDangerEditValue('');
      setDangerConfirm('');
      listDangerSettings().then(setDangerSettings).catch(() => {});
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Save failed';
      setDangerSaveMsg({ key, msg, ok: false });
    } finally {
      setDangerSaving(false);
    }
  };

  const handleConnTest = async (target: 'es' | 'llm') => {
    const blocked = demoBlocked(demo);
    if (blocked) { setConnTestResults(prev => ({ ...prev, [target]: { ok: false, detail: blocked, loading: false } })); return; } // demo: no doomed probe
    setConnTestResults(prev => ({ ...prev, [target]: { ok: false, detail: '', loading: true } }));
    try {
      const result = await testConnection(target);
      setConnTestResults(prev => ({ ...prev, [target]: { ...result, loading: false } }));
    } catch (e: unknown) {
      const detail = e instanceof Error ? e.message : 'Connection test failed';
      setConnTestResults(prev => ({ ...prev, [target]: { ok: false, detail, loading: false } }));
    }
  };

  // Internal-identifiers section, defined here so it can be interleaved into the
  // settings-group map (rendered immediately after the Discovery group).
  const internalIdentifiersSection = (
    <CollapsibleConfigSection
      id="internal-identifiers"
      title="Internal identifiers"
      collapsed={!!collapsed['Internal identifiers']}
      onToggle={() => toggleSection('Internal identifiers')}
      right={
        <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
          {idents?.last_scan?.last_scan && !scanning && (
            <span className="text-[11px] text-faint">
              last scan: {new Date(idents.last_scan.last_scan).toLocaleString()}
            </span>
          )}
          <button
            onClick={runScanNow}
            disabled={scanning}
            className="inline-flex items-center gap-1.5 rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent disabled:opacity-60 disabled:cursor-not-allowed"
          >
            {scanning && <Spinner size={11} />}
            {scanning ? 'Scanning…' : 'Scan now'}
          </button>
        </div>
      }
    >
      <div className="mb-2.5 text-[12px] text-dim">
        Redaction identifiers learned from your data and confirmed here — internal domain suffixes
        and bare hostnames are stripped from payloads before any cloud second opinion. On = soc-ai
        uses this to redact and classify; off = ignored. Reserved defaults are always on. Suggestions
        you don't want can be <strong>dismissed</strong> (removed for good) — distinct from turning
        one off, which keeps it in the list but unused. Dismissed suggestions are hidden; re-add one
        manually to restore it.
      </div>

      {identError && <div className="mb-2 text-[12px] text-danger">{identError}</div>}

      {idents == null && !identError ? (
        <LoadingState label="Loading internal identifiers…" />
      ) : idents ? (
        (['suffix', 'host', 'cidr'] as const).map((kind) => {
          const group = idents.groups.find((g) => g.kind === kind);
          const meta: Record<
            IdentifierKind,
            { title: string; placeholder: string; hint?: string }
          > = {
            suffix: { title: 'Domain suffixes', placeholder: '.corp.acme.com' },
            host: { title: 'Bare hostnames', placeholder: 'WIN11-01' },
            cidr: {
              title: 'Internal subnets (CIDRs)',
              placeholder: '10.50.0.0/24',
              // Suggest-first: a CIDR flips hosts internal↔external (changing
              // triage/enrichment), so detected subnets land off and never
              // auto-activate — the operator turns one on to apply it. Manual
              // adds are active immediately.
              hint: 'Detected subnets are suggestions — turn one on to treat it as internal. A subnet flips hosts internal↔external, so it is never activated automatically. Subnets you add manually apply right away.',
            },
          };
          return (
            <div key={kind}>
              {meta[kind].hint && (
                <div className="mb-1.5 mt-1 text-[11.5px] text-faint">{meta[kind].hint}</div>
              )}
              <ManagedList
                title={meta[kind].title}
                addPlaceholder={meta[kind].placeholder}
                rows={group?.rows ?? []}
                onAdd={(value) => identMutation(() => addInternalIdentifier(kind, value))}
                onSetActive={(id, active) => identMutation(() => setIdentifierActive(id, active))}
                onRemove={(id) => identMutation(() => removeIdentifier(id))}
                onDismiss={(id) => identMutation(() => dismissIdentifier(id))}
              />
            </div>
          );
        })
      ) : null}
    </CollapsibleConfigSection>
  );

  // Runbook re-embed card, interleaved right after the Retrieval (RAG) settings
  // group. The button is only meaningful once an embed model is configured AND
  // APPLIED (the endpoint reads the live setting, so a merely-staged edit still
  // 400s) — until then it renders disabled with the hint.
  const ragEmbedModelApplied = String(findSetting('rag_embed_model')?.value ?? '').trim() !== '';
  const ragReembedSection = (
    <div id="rag-reembed" className="mb-[22px] -mt-2.5">
      <div className="rounded-card border border-border bg-surface-1 px-[15px] py-[13px]">
        <div className="flex items-center gap-3.5">
          <div className="min-w-0 flex-1">
            <div className="text-[13px] font-semibold text-text">Re-embed runbooks</div>
            <div className="mt-1 text-[12px] text-dim">
              Embeds every runbook whose vector is missing (the gateway was down during a save) or
              stale (the embeddings model changed). Runbooks embed automatically on save; this is
              the catch-up pass. Requires an applied embeddings model above.
            </div>
          </div>
          <div className="flex-none">
            <button
              type="button"
              onClick={runReembed}
              disabled={reembedding || !ragEmbedModelApplied}
              className="inline-flex items-center gap-1.5 rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {reembedding && <Spinner size={11} />}
              {reembedding ? 'Re-embedding…' : 'Re-embed runbooks'}
            </button>
          </div>
        </div>
        {reembedResult && (
          <div
            className="mt-2 text-[12px]"
            style={{ color: reembedResult.ok ? '#12b76a' : '#f79009' }}
          >
            {reembedResult.embedded} embedded · {reembedResult.skipped} already current ·{' '}
            {reembedResult.failed} failed · {reembedResult.total} total
            {reembedResult.failed > 0 && ' — gateway trouble? Check the embeddings model + Diagnostics.'}
          </div>
        )}
        {reembedError && <div className="mt-2 text-[12px] text-danger">{reembedError}</div>}
      </div>
    </div>
  );

  // One server-driven settings group (id = the pre-computed collision-proof
  // slug from `layout`). The RAG group carries the re-embed card as an appendix.
  const renderGroup = (id: string, g: SettingGroup) => (
    <>
      <div id={id} className="mb-[22px] scroll-mt-6">
        <button
          type="button"
          onClick={() => toggleSection(g.title)}
          className="group w-full text-left"
        >
          <SectionTitle
            right={
              <span className="flex items-center gap-2 text-faint">
                <span className="font-mono text-[11px]">{g.items.length}</span>
                <ChevronRight
                  size={15}
                  className="transition-transform group-hover:text-text-2"
                  style={{ transform: collapsed[g.title] ? 'none' : 'rotate(90deg)' }}
                />
              </span>
            }
          >
            {g.title}
          </SectionTitle>
        </button>
        {!collapsed[g.title] && (
        <div className="overflow-hidden rounded-card border border-border bg-surface-1">
          {g.items.map((s) => (
            <div key={s.key} className="border-b border-border-faint px-[15px] py-[13px]">
              <div className="flex items-center gap-3.5">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[13px] font-semibold text-text">{s.label || s.key}</span>
                    <span className="font-mono text-[11px] text-faint">{s.key}</span>
                    <SourceBadge source={s.source} />
                    <ApplyBadge apply={s.apply} />
                    {staged[s.key] !== undefined && (
                      <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold" style={{ background: 'rgba(245,166,35,.14)', color: '#f5a623' }}>
                        unsaved
                      </span>
                    )}
                  </div>
                  <div className="mt-1 text-[12px] text-dim">{s.help}</div>
                </div>
                <div className="flex-none">{renderControl(s)}</div>
              </div>
              {/* #7 Auto-ack coupling note — auto-ack only acks FPs that get
                  INVESTIGATED, so it is inert without auto-triage running and a
                  medium/low floor. Warn when we can see the inert case; else hint. */}
              {s.key === 'auto_ack_fp_enabled' && autoAckOn && (
                <div
                  className="mt-2.5 flex items-start gap-2 rounded-control border px-3 py-2 text-[11.5px] leading-relaxed"
                  style={autoAckInert
                    ? { borderColor: 'rgba(245,166,35,.3)', background: 'rgba(245,166,35,.06)', color: '#f5a623' }
                    : { borderColor: '#161c25', background: 'rgba(148,163,184,.05)', color: '#94a3b8' }}
                >
                  <span className="flex-none pt-px">{autoAckInert ? '⚠' : 'ℹ'}</span>
                  <span>
                    Auto-ack only acks false positives that get investigated — it does nothing on its own.
                    {autoAckInert && scheduleOn === false && ' Scheduled auto-triage is off, so nothing is being investigated automatically.'}
                    {autoAckInert && floorTooHigh && ` The auto-triage severity floor is “${minSev}”, but high/critical are never auto-acked — so it can never fire.`}
                    {' '}To clear a backlog, run a sweep or enable continuous auto-investigate (in this group) and set its
                    severity floor to medium or low.
                  </span>
                </div>
              )}
            </div>
          ))}
        </div>
        )}
      </div>
      {g.title === 'Retrieval (RAG)' && ragReembedSection}
    </>
  );

  // Standalone System-parent sections, lifted out of the return so the
  // two-level layout loop can place them by id (see PANELS).
  const usersSection = (
      <CollapsibleConfigSection
        id="users"
        title="Users"
        right={<Users size={14} />}
        collapsed={!!collapsed['Users']}
        onToggle={() => toggleSection('Users')}
      >
        {resetPw && (
          <div className="mb-2.5 flex items-center gap-2.5 rounded-card border px-3.5 py-3" style={{ borderColor: 'rgba(245,166,35,.3)', background: 'rgba(245,166,35,.06)' }}>
            <span className="text-warn"><Key size={15} /></span>
            <div className="flex-1">
              <div className="text-[12px] font-semibold text-warn">
                New password for <span className="font-mono">{users.find((u) => u.id === resetPw.id)?.username ?? `user #${resetPw.id}`}</span> — save it now, it won't be shown again
              </div>
              <div className="mt-0.5 font-mono text-[12px] text-text">{resetPw.password}</div>
            </div>
            <button
              onClick={() => setResetPw(null)}
              className="text-[11.5px] text-faint hover:text-text"
            >
              ✕
            </button>
          </div>
        )}

        <div className="overflow-hidden rounded-card border border-border bg-surface-1">
          {users.map((u) => {
            const enabledAdminCount = users.filter((x) => x.role === 'admin' && !x.disabled).length;
            const isLastEnabledAdmin = u.role === 'admin' && !u.disabled && enabledAdminCount === 1;
            return (
              <div key={u.id} className="flex items-center gap-3 border-b border-border-faint px-[15px] py-3">
                <div className="flex-1 min-w-0">
                  <div className="text-[13px] font-semibold">{u.username}</div>
                  <div className="mt-0.5 flex items-center gap-2 text-[11.5px] text-faint">
                    <span
                      className="rounded px-1.5 py-0.5 text-[10.5px] font-semibold"
                      style={u.role === 'admin'
                        ? { background: 'rgba(99,180,255,.15)', color: '#63b4ff' }
                        : { background: 'rgba(148,163,184,.1)', color: '#94a3b8' }}
                    >
                      {u.role}
                    </span>
                    <span
                      className="rounded px-1.5 py-0.5 text-[10.5px] font-semibold"
                      style={u.disabled
                        ? { background: 'rgba(240,68,56,.1)', color: '#f04438' }
                        : { background: 'rgba(34,197,94,.1)', color: '#22c55e' }}
                    >
                      {u.disabled ? 'disabled' : 'enabled'}
                    </span>
                    {u.lastLoginAt && (
                      <span>last login {new Date(u.lastLoginAt).toLocaleDateString()}</span>
                    )}
                  </div>
                  {u.status && (
                    <div className="mt-0.5 truncate text-[11px] italic text-faint">{u.status}</div>
                  )}
                </div>
                <div className="flex items-center gap-2 flex-none">
                  <select
                    value={u.role}
                    onChange={(e) => {
                      const blocked = demoBlocked(demo);
                      if (blocked) { setUserError(blocked); return; } // demo: no doomed write
                      setUserError('');
                      setUserRole(u.id, e.target.value)
                        .then(() => setNonce((n) => n + 1))
                        .catch((e: unknown) => setUserError(e instanceof Error ? e.message : 'Failed to set role'));
                    }}
                    className="rounded-control border border-border-input bg-bg px-2 py-1 text-[11.5px] text-text outline-none focus:border-accent"
                  >
                    <option value="analyst">analyst</option>
                    <option value="admin">admin</option>
                  </select>
                  <button
                    onClick={() => {
                      if (isLastEnabledAdmin) return;
                      const blocked = demoBlocked(demo);
                      if (blocked) { setUserError(blocked); return; } // demo: no doomed write
                      setUserError('');
                      toggleUserDisabled(u.id)
                        .then(() => setNonce((n) => n + 1))
                        .catch((e: unknown) => setUserError(e instanceof Error ? e.message : 'Failed to toggle'));
                    }}
                    disabled={isLastEnabledAdmin}
                    className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    {u.disabled ? 'Enable' : 'Disable'}
                  </button>
                  <button
                    onClick={() => {
                      const blocked = demoBlocked(demo);
                      if (blocked) { setUserError(blocked); return; } // demo: no doomed write
                      resetUserPassword(u.id)
                        .then((r) => {
                          setResetPw({ id: u.id, password: r.password });
                          setNonce((n) => n + 1);
                        })
                        .catch((e: unknown) => setUserError(e instanceof Error ? e.message : 'Failed to reset password'));
                    }}
                    disabled={resetPw?.id === u.id}
                    className="rounded-[7px] border px-[11px] py-[5px] text-[11.5px] font-semibold text-danger hover:bg-[rgba(240,68,56,.12)] disabled:opacity-40 disabled:cursor-not-allowed"
                    style={{ borderColor: 'rgba(240,68,56,.3)' }}
                  >
                    Reset pw
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        {/* Create user form */}
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <input
            placeholder="username"
            value={newUser.username}
            onChange={(e) => setNewUser((u) => ({ ...u, username: e.target.value }))}
            className="w-[160px] rounded-control border border-border-input bg-bg px-3 py-1.5 font-mono text-[12.5px] text-text outline-none focus:border-accent"
          />
          <input
            type="password"
            placeholder="password"
            value={newUser.password}
            onChange={(e) => setNewUser((u) => ({ ...u, password: e.target.value }))}
            className="w-[160px] rounded-control border border-border-input bg-bg px-3 py-1.5 font-mono text-[12.5px] text-text outline-none focus:border-accent"
          />
          <select
            value={newUser.role}
            onChange={(e) => setNewUser((u) => ({ ...u, role: e.target.value }))}
            className="rounded-control border border-border-input bg-bg px-2 py-1.5 text-[12.5px] text-text outline-none focus:border-accent"
          >
            <option value="analyst">analyst</option>
            <option value="admin">admin</option>
          </select>
          <button
            onClick={() => {
              const blocked = demoBlocked(demo);
              if (blocked) { setUserError(blocked); return; } // demo: no doomed write
              setUserError('');
              createUser(newUser.username, newUser.password, newUser.role)
                .then(() => {
                  setNonce((n) => n + 1);
                  setNewUser({ username: '', password: '', role: 'analyst' });
                })
                .catch((e: unknown) => {
                  setUserError(e instanceof Error ? e.message : 'Error');
                });
            }}
            className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent"
          >
            Create user
          </button>
        </div>
        {userError && (
          <div className="mt-1.5 text-[12px] text-danger">{userError}</div>
        )}
      </CollapsibleConfigSection>
  );

  const apiTokensSection = (
      <CollapsibleConfigSection
        id="api-tokens"
        title="API tokens"
        collapsed={!!collapsed['API tokens']}
        onToggle={() => toggleSection('API tokens')}
        right={
          <span onClick={(e) => e.stopPropagation()}>
            <button
              onClick={() => {
                const blocked = demoBlocked(demo);
                if (blocked) { setTokenMsg(blocked); return; } // demo: no doomed write
                mintToken()
                  .then((t) => { setMinted(t); setNonce((n) => n + 1); })
                  .catch((e: unknown) => setTokenMsg(e instanceof Error ? e.message : 'Failed to mint token'));
              }}
              className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent"
            >
              + Mint token
            </button>
          </span>
        }
      >
        {tokenMsg && (
          <div
            className="mb-2.5 flex items-center gap-2.5 rounded-card border px-3.5 py-2.5 text-[12.5px] text-text-2"
            style={{ borderColor: 'rgba(75,139,245,.30)', background: 'rgba(75,139,245,.06)' }}
          >
            <span className="flex-1">{tokenMsg}</span>
            <button onClick={() => setTokenMsg('')} className="text-[11.5px] text-faint hover:text-text" aria-label="Dismiss">
              ✕
            </button>
          </div>
        )}
        {minted && (
          <div className="mb-2.5 flex items-center gap-2.5 rounded-card border px-3.5 py-3" style={{ borderColor: 'rgba(245,166,35,.3)', background: 'rgba(245,166,35,.06)' }}>
            <span className="text-warn"><Key size={15} /></span>
            <div className="flex-1">
              <div className="text-[12px] font-semibold text-warn">Copy this token now — it won't be shown again</div>
              <div className="mt-0.5 font-mono text-[12px] text-text">{minted}</div>
            </div>
            <button
              onClick={() => setMinted('')}
              className="text-[11.5px] text-faint hover:text-text"
            >
              ✕
            </button>
          </div>
        )}

        <div className="overflow-hidden rounded-card border border-border bg-surface-1">
          {data.tokens.map((tk) => (
            <div key={tk.id} className="flex items-center gap-3 border-b border-border-faint px-[15px] py-3">
              <span className="text-faint"><Key size={15} /></span>
              <div className="flex-1">
                <div className="text-[13px] font-semibold">{tk.name}</div>
                <div className="mt-0.5 font-mono text-[11.5px] text-faint">
                  {tk.prefix} · created {tk.created} · last used {tk.used}
                </div>
              </div>
              <button
                onClick={() => {
                  const blocked = demoBlocked(demo);
                  if (blocked) { setTokenMsg(blocked); return; } // demo: no doomed write
                  revokeToken(tk.id)
                    .then(() => setNonce((n) => n + 1))
                    .catch((e: unknown) => setTokenMsg(e instanceof Error ? e.message : 'Failed to revoke token'));
                }}
                className="rounded-[7px] border px-[11px] py-[5px] text-[11.5px] font-semibold text-danger hover:bg-[rgba(240,68,56,.12)]"
                style={{ borderColor: 'rgba(240,68,56,.3)' }}
              >
                Revoke
              </button>
            </div>
          ))}
        </div>
      </CollapsibleConfigSection>
  );

  const diagnosticsSection = (
      <CollapsibleConfigSection
        id="diagnostics"
        title="Diagnostics"
        collapsed={!!collapsed['Diagnostics']}
        onToggle={() => toggleSection('Diagnostics')}
      >
        <div className="text-[12px] text-dim mb-2">Read-only connectivity checks — safe to run anytime.</div>
        <div className="overflow-hidden rounded-card border border-border bg-surface-1">
          <div className="flex gap-3 px-4 py-3">
            {(['es', 'llm'] as const).map(target => {
              const res = connTestResults[target];
              return (
                <div key={target} className="flex items-center gap-2">
                  <button
                    className="rounded px-2.5 py-1 text-[11.5px] font-medium border border-border bg-surface-2 hover:bg-surface-3 transition-colors"
                    onClick={() => handleConnTest(target)}
                    disabled={res?.loading}
                  >
                    {res?.loading ? 'Testing…' : `Test ${target.toUpperCase()}`}
                  </button>
                  {res && !res.loading && (
                    <span className="text-[11px]" style={{ color: res.ok ? '#12b76a' : '#f04438' }}>
                      {res.ok ? '✓' : '✗'} {res.detail}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </CollapsibleConfigSection>
  );

  const dangerZoneSection = (
      <div
        id="danger-zone"
        className="overflow-hidden rounded-card border scroll-mt-6"
        style={{
          borderColor: 'rgba(240,68,56,.35)',
          background: 'linear-gradient(180deg,rgba(240,68,56,.05),rgba(11,14,19,0) 60%),#0b0e13',
        }}
      >
        {/* Header — its own chevron folds the settings rows (custom colored
            header, not a SectionTitle, so the toggle lives inline here). */}
        <button
          type="button"
          onClick={() => toggleSection('Danger Zone')}
          className="group flex w-full items-center gap-[9px] border-b border-[rgba(240,68,56,.2)] px-4 py-[13px] text-left"
          style={{ background: 'rgba(240,68,56,.06)' }}
        >
          <ShieldAlert size={15} className="text-[#f04438]" />
          <span className="text-[13px] font-semibold text-[#f04438]">Danger Zone</span>
          <span className="ml-auto text-[11px] text-text-muted">Connection changes may need a restart</span>
          <ChevronRight
            size={15}
            className="text-[#f04438] transition-transform"
            style={{ transform: collapsed['Danger Zone'] ? 'none' : 'rotate(90deg)' }}
          />
        </button>

        {/* Settings rows */}
        {collapsed['Danger Zone'] ? null : dangerLoading ? (
          <div className="px-4 py-6 text-[12px] text-text-muted">Loading…</div>
        ) : dangerError ? (
          <div className="px-4 py-4 text-[12px] text-faint">{dangerError}</div>
        ) : (
          <div>
            {dangerSettings.map(s => {
              const isEditing = dangerEditKey === s.key;
              const confirmOk = dangerConfirm === s.key;
              const saveMsg = dangerSaveMsg?.key === s.key ? dangerSaveMsg : null;
              return (
                <div key={s.key} className="border-b border-border-faint px-4 py-3 last:border-0">
                  <div className="flex items-center gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="text-[12.5px] font-medium text-text-primary">{s.label}</div>
                      <div className="text-[10.5px] text-text-muted font-mono">{s.key}</div>
                    </div>
                    {s.type === 'secret' && (
                      <span
                        className="rounded px-1.5 py-0.5 text-[10px] font-semibold"
                        style={{
                          background: s.isSet ? 'rgba(18,183,106,.15)' : 'rgba(240,68,56,.12)',
                          color: s.isSet ? '#12b76a' : '#f04438',
                        }}
                      >
                        {s.isSet ? 'Set' : 'Unset'}
                      </span>
                    )}
                    {s.source !== 'unset' && (
                      <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold bg-surface-2 text-text-muted border border-border">
                        {s.source === 'env' ? 'env' : 'db'}
                      </span>
                    )}
                    {!isEditing && (
                      <button
                        className="rounded px-2 py-0.5 text-[11px] border border-border bg-surface-2 hover:bg-surface-3 transition-colors"
                        onClick={() => {
                          setDangerEditKey(s.key);
                          setDangerEditValue('');
                          setDangerConfirm('');
                          setDangerSaveMsg(null);
                        }}
                      >
                        Edit
                      </button>
                    )}
                  </div>

                  {isEditing && (
                    <div className="mt-2.5 space-y-2">
                      <div>
                        <label className="block text-[11px] text-text-muted mb-1">
                          {s.type === 'secret' ? 'New value (write-only)' : 'Value'}
                        </label>
                        <input
                          type={s.type === 'secret' ? 'password' : 'text'}
                          className="w-full rounded border border-border bg-surface-2 px-2.5 py-1.5 text-[12px] font-mono text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-[rgba(240,68,56,.5)]"
                          placeholder={s.type === 'secret' ? '••••••••' : s.label}
                          value={dangerEditValue}
                          onChange={e => setDangerEditValue(e.target.value)}
                          autoComplete="new-password"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-text-muted mb-1">
                          Type <span className="font-mono text-[#f04438]">{s.key}</span> to confirm
                        </label>
                        <input
                          type="text"
                          className="w-full rounded border border-border bg-surface-2 px-2.5 py-1.5 text-[12px] font-mono text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-[rgba(240,68,56,.5)]"
                          placeholder={s.key}
                          value={dangerConfirm}
                          onChange={e => setDangerConfirm(e.target.value)}
                          autoComplete="off"
                        />
                      </div>
                      {!s.hot && (
                        <div className="flex items-center gap-1.5 text-[11px] text-[#f79009]">
                          <span>⚠</span>
                          <span>Service restart required for this change to take effect</span>
                        </div>
                      )}
                      {saveMsg && (
                        <div className="text-[11.5px]" style={{ color: saveMsg.ok ? '#12b76a' : '#f04438' }}>
                          {saveMsg.msg}
                        </div>
                      )}
                      <div className="flex gap-2">
                        <button
                          className="rounded px-3 py-1 text-[11.5px] font-medium transition-colors"
                          style={{
                            background: confirmOk && dangerEditValue ? 'rgba(240,68,56,.85)' : 'rgba(240,68,56,.2)',
                            color: confirmOk && dangerEditValue ? '#fff' : 'rgba(240,68,56,.5)',
                            cursor: confirmOk && dangerEditValue ? 'pointer' : 'not-allowed',
                          }}
                          onClick={() => handleDangerSave(s.key)}
                          disabled={!confirmOk || !dangerEditValue || dangerSaving}
                        >
                          {dangerSaving ? 'Saving…' : 'Save'}
                        </button>
                        <button
                          className="rounded px-3 py-1 text-[11.5px] border border-border bg-surface-2 hover:bg-surface-3 transition-colors"
                          onClick={() => {
                            setDangerEditKey(null);
                            setDangerEditValue('');
                            setDangerConfirm('');
                            setDangerSaveMsg(null);
                          }}
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
  );

  // Renderable node per standalone-panel id; PANELS placement decides where
  // each lands in the two-level layout.
  const panelNodes: Record<string, ReactNode> = {
    'agent-tools': (
      <AgentToolsPanel
        collapsed={!!collapsed['Agent tools']}
        onToggleCollapse={() => toggleSection('Agent tools')}
      />
    ),
    'notifications-webhook': (
      <NotificationsPanel
        collapsed={!!collapsed['Notification webhook']}
        onToggleCollapse={() => toggleSection('Notification webhook')}
      />
    ),
    runbooks: (
      <RunbooksPanel
        collapsed={!!collapsed['Runbooks']}
        onToggleCollapse={() => toggleSection('Runbooks')}
      />
    ),
    'egress-policy': (
      <EgressPolicyPanel
        collapsed={!!collapsed['Egress policy']}
        onToggleCollapse={() => toggleSection('Egress policy')}
      />
    ),
    'internal-identifiers': internalIdentifiersSection,
    'redaction-preview': (
      <RedactionPreviewPanel
        collapsed={!!collapsed['Redaction preview']}
        onToggleCollapse={() => toggleSection('Redaction preview')}
      />
    ),
    'data-sources': (
      <DataSourcesPanel
        collapsed={!!collapsed['Data sources']}
        onToggleCollapse={() => toggleSection('Data sources')}
      />
    ),
    'detection-tuning': (
      <DetectionTuningPanel
        collapsed={!!collapsed['Detection tuning']}
        onToggleCollapse={() => toggleSection('Detection tuning')}
      />
    ),
    'api-keys': (
      <ApiKeysPanel
        collapsed={!!collapsed['API keys']}
        onToggleCollapse={() => toggleSection('API keys')}
      />
    ),
    users: usersSection,
    'api-tokens': apiTokensSection,
    maintenance: (
      <MaintenancePanel
        collapsed={!!collapsed['Scheduled maintenance']}
        onToggleCollapse={() => toggleSection('Scheduled maintenance')}
      />
    ),
    diagnostics: diagnosticsSection,
    'danger-zone': dangerZoneSection,
  };

  return (
    <div className="mx-auto flex max-w-workstation gap-6 px-[22px] pb-[60px] pt-5">
      <aside className="hidden w-[190px] flex-none lg:block">
        <ConfigNav groups={layout} activeId={activeId} onNavigate={navigateToSection} />
      </aside>
      <div className="min-w-0 max-w-permalink flex-1">
      <div className="text-[20px] font-semibold tracking-[-.015em]">Config</div>
      <div className="mb-[18px] mt-0.5 text-[13px] text-dim">
        Runtime settings · users · API tokens. Source badges show whether a value is set in the database or pinned by an
        environment variable.
      </div>

      {/* Two-level body: parent header, then its sub-sections (server-driven
          settings groups + standalone panels), in exactly the nav's order. */}
      {layout.map((p) => (
        <Fragment key={p.label}>
          <div className="mb-[14px] mt-[36px] flex items-center gap-2.5">
            <div className="text-[11.5px] font-bold uppercase tracking-[.09em] text-accent">
              {p.label}
            </div>
            <div className="h-px flex-1 bg-border" />
          </div>
          {p.children.map((c) => (
            <Fragment key={c.id}>
              {c.kind === 'group' ? renderGroup(c.id, c.group) : (panelNodes[c.id] ?? null)}
            </Fragment>
          ))}
        </Fragment>
      ))}

      {/* Sticky save/apply bar (FIX #8) — settings above stage locally; nothing
          persists until Apply. The bar is only shown when there are staged edits
          or a fresh apply result to report, removing the "did that save?"
          ambiguity of the old per-field auto-save. */}
      {(isDirty || applyResult) && (
        <div className="sticky bottom-4 z-20 mt-4 flex items-center gap-3 rounded-card border border-border-strong bg-surface-2/95 px-4 py-3 shadow-lg backdrop-blur">
          <div className="min-w-0 flex-1 text-[12.5px]">
            {isDirty ? (
              <span className="text-text">
                <span className="font-semibold">{dirtyKeys.length}</span> unsaved change{dirtyKeys.length === 1 ? '' : 's'}
                <span className="ml-1 text-dim">— not applied yet</span>
              </span>
            ) : applyResult ? (
              <span style={{ color: applyResult.ok ? '#12b76a' : '#f04438' }}>
                {applyResult.ok ? '✓ ' : '✗ '}{applyResult.msg}
              </span>
            ) : null}
          </div>
          <button
            onClick={discardStaged}
            disabled={!isDirty || applying}
            className="rounded-[7px] border border-border-strong bg-surface-3 px-[13px] py-[6px] text-[12px] font-semibold text-text hover:border-accent disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Discard
          </button>
          <button
            onClick={applyStaged}
            disabled={!isDirty || applying}
            className="inline-flex items-center gap-1.5 rounded-[7px] border border-accent bg-accent/15 px-[13px] py-[6px] text-[12px] font-semibold text-accent hover:bg-accent/25 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {applying && <Spinner size={12} />}
            {applying ? 'Applying…' : `Apply changes${isDirty ? ` (${dirtyKeys.length})` : ''}`}
          </button>
        </div>
      )}
      </div>
    </div>
  );
}
