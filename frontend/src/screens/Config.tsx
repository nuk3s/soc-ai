import { ChevronRight, Key, ShieldAlert, Users } from 'lucide-react';
import { Fragment, useEffect, useMemo, useState } from 'react';
import { useLocation } from 'react-router-dom';
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
import { AboutPanel } from './AboutPanel';
import { MaintenancePanel } from './MaintenancePanel';
import { RunbooksPanel } from './RunbooksPanel';
import { addInternalIdentifier, createUser, dismissIdentifier, getConfig, getDiscoveryScan, getGatewayModels, getInternalIdentifiers, getModelBattery, getModelFitness, listDangerSettings, listUsers, mintToken, reembedRunbooks, removeIdentifier, resetUserPassword, revokeToken, saveDangerSetting, setIdentifierActive, setSetting, setUserRole, startModelBattery, startDiscoveryScan, testConnection, toggleUserDisabled } from '../lib/api';
import type { BatteryRecommendation, ModelBatteryStatus } from '../lib/api';
import type { IdentifierKind, InternalIdentifiers, ModelFitness, RagReembedResult } from '../lib/api';
import { demoBlocked, useDemo } from '../lib/demo';
import { useAsync } from '../lib/useAsync';
import type { AdminUser, ConnTestResult, DangerSetting, Setting, SettingGroup } from '../lib/types';
import { ConfigNav, ConfigNavSelect } from './ConfigNav';
import {
  type ConfigParent,
  SUB_ANCHOR_HOSTS,
  buildConfigLayout,
  keyToSectionId,
} from '../lib/configLayout';

/** Nearest scrollable ancestor (the AppShell's overflow-y-auto content pane). */
function scrollContainerOf(el: HTMLElement): HTMLElement | null {
  for (let p = el.parentElement; p; p = p.parentElement) {
    const oy = getComputedStyle(p).overflowY;
    if (oy === 'auto' || oy === 'scroll') return p;
  }
  return null;
}

// The Config-page information architecture (PARENT_ORDER, PANELS, the layout
// builder) lives in lib/configLayout so the command palette derives the SAME
// section ids this page renders.

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
      {!loading && fitness?.cached && fitness.checked_at && (
        <span className="text-[11px] text-faint" title="Served from the daily cache — Check fitness re-measures">
          {_batteryAge(fitness.checked_at)}
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

/** Age string for a stored battery result ("2h ago"); empty when unknown. */
function _batteryAge(iso: string | null): string {
  if (!iso) return '';
  const ms = Date.now() - new Date(iso + (iso.endsWith('Z') ? '' : 'Z')).getTime();
  if (!Number.isFinite(ms) || ms < 0) return '';
  const h = ms / 3_600_000;
  if (h < 1) return `${Math.max(1, Math.round(ms / 60_000))}m ago`;
  if (h < 48) return `${Math.round(h)}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

/** The on-demand second tier of the fitness feature: probe the model under
 * every structured-output configuration, show per-config results, and offer
 * the deterministic recommendation as a one-click stage (never auto-apply). */
function ModelBatteryPanel({
  battery,
  running,
  demo,
  onRun,
  onRunAll,
  onApply,
  recApplied,
}: {
  battery: ModelBatteryStatus | null;
  running: boolean;
  demo: boolean;
  onRun: () => void;
  onRunAll: () => void;
  onApply: (rec: BatteryRecommendation) => void;
  /** true = the live knob values already match the recommendation. */
  recApplied: boolean;
}) {
  const result = battery?.result ?? null;
  return (
    <div className="flex flex-col items-end gap-1">
      <div className="flex items-center gap-2">
        {running && (
          <span className="text-[11px] text-faint">
            Battery: {battery?.current_config ?? '…'} ({(battery?.completed ?? 0) + 1}/
            {battery?.total ?? 4})…
          </span>
        )}
        {!running && result && battery?.stored_at && (
          <span className="text-[11px] text-faint">{_batteryAge(battery.stored_at)}</span>
        )}
        <button
          type="button"
          className="rounded border border-border bg-surface-2 px-2 py-0.5 text-[11px] font-medium hover:bg-surface-3 transition-colors disabled:opacity-50"
          onClick={onRun}
          disabled={running || demo}
          title={
            demo
              ? 'Unavailable in the demo (no model egress)'
              : 'Probe this model under every structured-output configuration (tool / native / prompted / tool+required). Minutes on a slow backend.'
          }
        >
          Run full battery
        </button>
        <button
          type="button"
          className="rounded border border-border bg-surface-2 px-2 py-0.5 text-[11px] font-medium hover:bg-surface-3 transition-colors disabled:opacity-50"
          onClick={onRunAll}
          disabled={running || demo}
          title={
            demo
              ? 'Unavailable in the demo (no model egress)'
              : 'Re-measure fitness AND run the full battery in one go'
          }
        >
          Run all checks
        </button>
      </div>
      {!running && result && (
        <table className="text-[11px] text-dim">
          <tbody>
            {result.configs.map((c) => {
              const label = c.tool_choice_required ? `${c.output_mode}+required` : c.output_mode;
              return (
                <tr key={label}>
                  <td className="pr-3 font-mono">{label}</td>
                  <td className="pr-3 text-right">
                    {c.ok}/{c.n}
                  </td>
                  <td className="text-right">{c.elapsed_s.toFixed(1)}s</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {!running && result?.recommendation && recApplied && (
        <span
          className="text-[11px] text-success"
          title={result.recommendation.reason}
        >
          ✓ Already on the recommended settings ({result.recommendation.config})
        </span>
      )}
      {!running && result?.recommendation && !recApplied && (
        <div className="flex items-center gap-2 rounded border border-border bg-surface-2 px-2 py-1">
          <span className="max-w-[260px] text-[11px] text-text" title={result.recommendation.reason}>
            {result.recommendation.reason}
          </span>
          <button
            type="button"
            className="rounded border border-accent px-2 py-0.5 text-[11px] font-semibold text-accent hover:bg-accent/10 transition-colors"
            onClick={() => onApply(result.recommendation!)}
            title="Stage these knob values into the pending config edits (Apply below saves them)"
          >
            Apply
          </button>
        </div>
      )}
      {!running && battery?.error && (
        <span className="max-w-[280px] truncate text-[11px] text-danger" title={battery.error}>
          battery failed: {battery.error}
        </span>
      )}
    </div>
  );
}

export function Config() {
  const demo = useDemo(); // read-only demo: config writes show a note, never POST
  const [nonce, setNonce] = useState(0);
  const location = useLocation();
  // Collapsed config sections — persisted so a fold survives leaving the page
  // (the dogfood walkthrough found collapse state silently reset every visit).
  // Deep-links and nav clicks auto-expand their target.
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>(() => {
    try {
      return JSON.parse(localStorage.getItem('soc-ai:config:collapsed') || '{}') as Record<
        string,
        boolean
      >;
    } catch {
      return {};
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem('soc-ai:config:collapsed', JSON.stringify(collapsed));
    } catch {
      /* private mode — folds just won't persist */
    }
  }, [collapsed]);
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

  const runFitness = (force = false) => {
    setFitnessLoading(true);
    getModelFitness(force)
      .then((r) => setFitness(r))
      // Fail-soft: a probe/gateway/permission error must not surface as an error
      // chip — clear the stale grade and stay neutral.
      .catch(() => setFitness(null))
      .finally(() => setFitnessLoading(false));
  };

  // ── Fitness battery (design spec 2026-08-05) ────────────────────────────
  const [battery, setBattery] = useState<ModelBatteryStatus | null>(null);
  const batteryModel = String(currentAnalystModel);

  // Load the stored result for the selected model; keep polling while running.
  useEffect(() => {
    if (!batteryModel) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = () => {
      getModelBattery(batteryModel)
        .then((r) => {
          if (cancelled) return;
          setBattery(r);
          if (r.running) timer = setTimeout(poll, 2000);
        })
        .catch(() => {
          if (!cancelled) setBattery(null);
        });
    };
    setBattery(null); // model changed — a stale battery result would mislead
    poll();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [batteryModel]);

  const runBattery = () => {
    startModelBattery(batteryModel)
      .then(() => getModelBattery(batteryModel))
      .then((r) => setBattery(r))
      // 409 (already running) also lands here: the poll below re-syncs.
      .catch(() => getModelBattery(batteryModel).then(setBattery).catch(() => undefined))
      .finally(() => {
        // Kick the polling effect even if the effect's timer already fired.
        setBattery((b) => (b ? { ...b, running: true } : b));
      });
  };

  // Does the CURRENT state (staged edit wins over server value) already match
  // the battery's recommendation? Then the banner reads "already on the
  // recommended settings" instead of nagging Apply (dogfood 2026-08-05).
  const currentKnob = (key: string) => {
    const server = data?.groups.flatMap((g) => g.items).find((i) => i.key === key)?.value;
    return staged[key] ?? String(server ?? '');
  };
  const rec = battery?.result?.recommendation ?? null;
  const recApplied =
    !!rec &&
    currentKnob('synthesizer_output_mode') === rec.synthesizer_output_mode &&
    currentKnob('analyst_tool_choice_required') === String(rec.analyst_tool_choice_required);

  // One click, both measurements: force a fresh fitness check and start the
  // battery together (dogfood 2026-08-05).
  const runAllChecks = () => {
    runFitness(true);
    runBattery();
  };

  // Stage (never save) the recommendation's two knob values — they ride the
  // normal Apply/Discard flow, audit trail included.
  const applyBatteryRec = (rec: BatteryRecommendation) => {
    const serverOf = (key: string) =>
      String(data?.groups.flatMap((g) => g.items).find((i) => i.key === key)?.value ?? '');
    stage('synthesizer_output_mode', rec.synthesizer_output_mode, serverOf('synthesizer_output_mode'));
    stage(
      'analyst_tool_choice_required',
      String(rec.analyst_tool_choice_required),
      serverOf('analyst_tool_choice_required'),
    );
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

  // ── Master-detail section model ────────────────────────────────────────────
  // The two-level nav (lib/configLayout) is the master; the content pane renders
  // ONLY the selected section. Replaces the single 32,000px scroll of all 31
  // sections the dogfood walkthrough measured (2026-08-01) — and with it the
  // scroll-spy, which has no long page left to track.
  const layout = useMemo<ConfigParent[]>(() => buildConfigLayout(data?.groups), [data?.groups]);
  const flatSections = useMemo(() => layout.flatMap((p) => p.children), [layout]);
  const keyToSection = useMemo(() => keyToSectionId(layout), [layout]);

  // Selection: explicit choice (hash / nav click) > last-visited (localStorage)
  // > the first section. Stored so "come back to where I was tuning" survives.
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [storedSection] = useState<string | null>(() => {
    try {
      return localStorage.getItem('soc-ai:config:section');
    } catch {
      return null;
    }
  });
  const validId = (id: string | null): id is string =>
    !!id && flatSections.some((s) => s.id === id);
  const effectiveId = validId(selectedId)
    ? selectedId
    : validId(storedSection)
      ? storedSection
      : (flatSections[0]?.id ?? '');
  useEffect(() => {
    if (!effectiveId) return;
    try {
      localStorage.setItem('soc-ai:config:section', effectiveId);
    } catch {
      /* private mode — selection just won't persist */
    }
  }, [effectiveId]);

  // The setting row to flash after a jump (search hit, apply-bar chip, or the
  // palette's navigate('/config#…', { state: { highlightKey } }) hand-off).
  const [highlightKey, setHighlightKey] = useState<string | null>(null);
  useEffect(() => {
    if (!highlightKey) return;
    const el = document.querySelector(`[data-setting-key="${highlightKey}"]`);
    (el as HTMLElement | null)?.scrollIntoView?.({ behavior: 'auto', block: 'center' });
    const t = setTimeout(() => setHighlightKey(null), 2500);
    return () => clearTimeout(t);
  }, [highlightKey, effectiveId]);

  // ── Settings search (spans every section) ──────────────────────────────────
  const [query, setQuery] = useState('');
  const trimmedQuery = query.trim().toLowerCase();
  const searching = trimmedQuery.length >= 2;

  // Nav click / chip click / search hit: select the section, expand it if its
  // header was folded, sync the hash (deep-linkable), and start the fresh
  // section at the top of the content pane.
  const navigateToSection = (id: string) => {
    const label = flatSections.find((s) => s.id === id)?.label;
    if (label) setCollapsed((c) => ({ ...c, [label]: false }));
    setSelectedId(id);
    setQuery('');
    history.replaceState(null, '', `#${id}`);
    requestAnimationFrame(() => {
      const el = document.getElementById(id);
      const sc = el ? scrollContainerOf(el) : null;
      if (sc) sc.scrollTop = 0;
    });
  };

  // Deep-link entry: /config#<section> selects that section (dashboard links,
  // the sidebar version line, the palette). A sub-anchor that lives INSIDE a
  // section (#rag-reembed) selects its host section, then scrolls to the card.
  // Router state may carry a highlightKey (palette jump-to-setting).
  useEffect(() => {
    if (!flatSections.length) return;
    const raw = location.hash.replace('#', '');
    const state = (location.state ?? null) as { highlightKey?: string } | null;
    let target = raw;
    let subAnchor: string | null = null;
    if (raw && !flatSections.some((s) => s.id === raw)) {
      const hostLabel = SUB_ANCHOR_HOSTS[raw];
      const host = hostLabel ? flatSections.find((s) => s.label === hostLabel) : undefined;
      if (host) {
        target = host.id;
        subAnchor = raw;
      } else {
        target = '';
      }
    }
    if (target) {
      const label = flatSections.find((s) => s.id === target)?.label;
      if (label) setCollapsed((c) => ({ ...c, [label]: false }));
      setSelectedId(target);
    }
    if (state?.highlightKey) setHighlightKey(state.highlightKey);
    if (subAnchor) {
      const t = setTimeout(
        () => document.getElementById(subAnchor)?.scrollIntoView?.({ behavior: 'auto', block: 'start' }),
        60,
      );
      return () => clearTimeout(t);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [flatSections, location.hash, location.key]);

  // Search corpus: every setting (label + key + help) in every section, every
  // section name, and the Danger Zone settings. All already client-side — the
  // page had 275 controls and no way to find one (dogfood 2026-08-01).
  interface SearchHit {
    kind: 'setting' | 'section';
    settingKey?: string;
    label: string;
    haystack: string;
    sectionId: string;
    sectionLabel: string;
    parent: string;
  }
  const searchIndex = useMemo<SearchHit[]>(() => {
    const out: SearchHit[] = [];
    for (const p of layout) {
      for (const c of p.children) {
        out.push({
          kind: 'section',
          label: c.label,
          haystack: `${c.label} ${p.label}`.toLowerCase(),
          sectionId: c.id,
          sectionLabel: c.label,
          parent: p.label,
        });
        if (c.kind === 'group') {
          for (const it of c.group.items) {
            out.push({
              kind: 'setting',
              settingKey: it.key,
              label: it.label || it.key,
              haystack: `${it.label} ${it.key} ${it.help}`.toLowerCase(),
              sectionId: c.id,
              sectionLabel: c.label,
              parent: p.label,
            });
          }
        }
      }
    }
    for (const ds of dangerSettings) {
      out.push({
        kind: 'setting',
        settingKey: ds.key,
        label: ds.label,
        haystack: `${ds.label} ${ds.key}`.toLowerCase(),
        sectionId: 'danger-zone',
        sectionLabel: 'Danger Zone',
        parent: 'System',
      });
    }
    return out;
  }, [layout, dangerSettings]);

  // Every whitespace-separated term must match; ranked label-match, then
  // key/help match, sections after settings within a tier.
  const searchHits = useMemo<SearchHit[]>(() => {
    if (!searching) return [];
    const terms = trimmedQuery.split(/\s+/);
    const scored: { h: SearchHit; score: number }[] = [];
    for (const h of searchIndex) {
      if (!terms.every((t) => h.haystack.includes(t))) continue;
      const labelHit = terms.every((t) => h.label.toLowerCase().includes(t));
      scored.push({ h, score: (labelHit ? 0 : 2) + (h.kind === 'section' ? 1 : 0) });
    }
    return scored
      .sort((a, b) => a.score - b.score)
      .slice(0, 50)
      .map((s) => s.h);
  }, [searchIndex, searching, trimmedQuery]);

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

  // Bulk identifier mutation: fire every per-row call, report failures honestly,
  // refetch ONCE at the end (not per row). Same demo gate as identMutation.
  const identBulk = (makeAll: () => Promise<unknown>[]) => {
    const blocked = demoBlocked(demo);
    if (blocked) {
      setIdentError(blocked);
      return;
    }
    setIdentError('');
    void Promise.allSettled(makeAll()).then((results) => {
      const failed = results.filter((r) => r.status === 'rejected').length;
      if (failed) setIdentError(`${failed} of ${results.length} bulk actions failed`);
      refetchIdents();
    });
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

  if (loading && !data) return <div className="p-6"><LoadingState label="Loading settings…" /></div>;
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

  // Drop ONE staged edit (the apply-bar chip's ✕) — the rest stay staged.
  const discardOne = (key: string) => {
    setStaged((s) => {
      const next = { ...s };
      delete next[key];
      return next;
    });
    setApplyErrors((e) => {
      const next = { ...e };
      delete next[key];
      return next;
    });
    setFormNonce((n) => n + 1); // remount uncontrolled inputs so the field resets
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
            onCheck={() => runFitness(true)}
          />
          <ModelBatteryPanel
            battery={battery}
            running={!!battery?.running}
            demo={demo}
            onRun={runBattery}
            onRunAll={runAllChecks}
            onApply={applyBatteryRec}
            recApplied={recApplied}
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
            onCheck={() => runFitness(true)}
          />
          <ModelBatteryPanel
            battery={battery}
            running={!!battery?.running}
            demo={demo}
            onRun={runBattery}
            onRunAll={runAllChecks}
            onApply={applyBatteryRec}
            recApplied={recApplied}
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
                searchable
                pageSize={25}
                bulk={{
                  onSetActiveMany: (ids, active) =>
                    identBulk(() => ids.map((id) => setIdentifierActive(id, active))),
                  onDismissMany: (ids) => identBulk(() => ids.map((id) => dismissIdentifier(id))),
                }}
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
            <div
              key={s.key}
              data-setting-key={s.key}
              data-highlighted={highlightKey === s.key ? 'true' : undefined}
              className="border-b border-border-faint px-[15px] py-[13px] transition-shadow"
              style={
                highlightKey === s.key
                  ? { boxShadow: 'inset 0 0 0 2px rgb(var(--accent) / 0.7)' }
                  : undefined
              }
            >
              {/* items-start (not center): tall controls like the analyst-model
                  cell (select + fitness + battery) otherwise float the title to
                  the middle of the cell (dogfood 2026-08-05). */}
              <div className="flex items-start gap-3.5">
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
    about: (
      <AboutPanel
        collapsed={!!collapsed['About']}
        onToggleCollapse={() => toggleSection('About')}
        refreshKey={nonce}
      />
    ),
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

  const searchInput = (className: string) => (
    <input
      value={query}
      onChange={(e) => setQuery(e.target.value)}
      placeholder="Search settings"
      aria-label="Search settings"
      className={`rounded-control border border-border-input bg-bg px-3 py-1.5 text-[12.5px] text-text outline-none placeholder:text-faint focus:border-accent ${className}`}
    />
  );

  // The section chosen by the master nav — the ONLY section in the DOM.
  const selectedPane = (() => {
    for (const p of layout) {
      const c = p.children.find((child) => child.id === effectiveId);
      if (!c) continue;
      return (
        <Fragment key={c.id}>
          <div className="mb-[14px] flex items-center gap-2.5">
            <div className="text-[11.5px] font-bold uppercase tracking-[.09em] text-accent">
              {p.label}
            </div>
            <div className="h-px flex-1 bg-border" />
          </div>
          {c.kind === 'group' ? renderGroup(c.id, c.group) : (panelNodes[c.id] ?? null)}
        </Fragment>
      );
    }
    return null;
  })();

  // Search results replace the pane while a query is live; a hit jumps to the
  // owning section and flashes the exact row.
  const resultsPane = (
    <div className="overflow-hidden rounded-card border border-border bg-surface-1">
      {searchHits.length === 0 ? (
        <div className="px-4 py-6 text-[12.5px] text-faint">
          No settings match “{query.trim()}”.
        </div>
      ) : (
        searchHits.map((h) => (
          <button
            key={h.kind === 'setting' ? h.settingKey : `section-${h.sectionId}`}
            type="button"
            data-testid={`search-result-${h.kind === 'setting' ? h.settingKey : `section-${h.sectionId}`}`}
            onClick={() => {
              navigateToSection(h.sectionId);
              if (h.kind === 'setting') setHighlightKey(h.settingKey ?? null);
            }}
            className="flex w-full items-center gap-3 border-b border-border-faint px-[15px] py-[11px] text-left last:border-0 hover:bg-surface-2"
          >
            <div className="min-w-0 flex-1">
              <span className="text-[13px] font-semibold text-text">{h.label}</span>
              {h.kind === 'setting' && (
                <span className="ml-2 font-mono text-[11px] text-faint">{h.settingKey}</span>
              )}
            </div>
            <span className="flex-none text-[11.5px] text-faint">
              {h.parent} / {h.sectionLabel}
            </span>
          </button>
        ))
      )}
    </div>
  );

  return (
    <div className="mx-auto flex max-w-workstation gap-6 px-[22px] pb-[60px] pt-5">
      <aside className="hidden w-[190px] flex-none lg:block">
        {searchInput('mb-3 w-full')}
        <ConfigNav groups={layout} activeId={effectiveId} onNavigate={navigateToSection} />
      </aside>
      <div className="min-w-0 max-w-permalink flex-1">
      <ConfigNavSelect groups={layout} activeId={effectiveId} onNavigate={navigateToSection} />
      <div className="text-[20px] font-semibold tracking-[-.015em]">Config</div>
      <div className="mb-[14px] mt-0.5 text-[13px] text-dim">
        Runtime settings · users · API tokens. Source badges show whether a value is set in the database or pinned by an
        environment variable.
      </div>
      {searchInput('mb-[14px] w-full lg:hidden')}

      {searching ? resultsPane : selectedPane}

      {/* Sticky save/apply bar (FIX #8) — settings above stage locally; nothing
          persists until Apply. The bar is only shown when there are staged edits
          or a fresh apply result to report, removing the "did that save?"
          ambiguity of the old per-field auto-save. */}
      {(isDirty || applyResult) && (
        <div className="sticky bottom-4 z-20 mt-4 flex items-center gap-3 rounded-card border border-border-strong bg-surface-2/95 px-4 py-3 shadow-lg backdrop-blur">
          <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1.5 text-[12.5px]">
            {isDirty ? (
              <>
                {/* Every staged edit is NAMED: a chip per dirty setting. Click →
                    jump to the owning section with the row flashed (an edit
                    staged screens ago is findable, not a blind commit); ✕ →
                    discard just that one. Tooltip carries old → new. */}
                <span className="mr-1 text-text">
                  <span className="font-semibold">{dirtyKeys.length}</span> unsaved
                </span>
                {dirtyKeys.map((key) => {
                  const s = findSetting(key);
                  const label = s?.label || key;
                  return (
                    <span
                      key={key}
                      data-testid={`chip-${key}`}
                      role="button"
                      tabIndex={0}
                      title={`${String(s?.value ?? '')} → ${staged[key]}`}
                      onClick={() => {
                        navigateToSection(keyToSection[key] ?? effectiveId);
                        setHighlightKey(key);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          navigateToSection(keyToSection[key] ?? effectiveId);
                          setHighlightKey(key);
                        }
                      }}
                      className="inline-flex cursor-pointer items-center gap-1.5 rounded-chip border border-border-strong bg-surface-3 px-2 py-0.5 text-[11.5px] font-medium text-text hover:border-accent"
                    >
                      {label}
                      <button
                        type="button"
                        aria-label={`Discard ${label}`}
                        onClick={(e) => {
                          e.stopPropagation();
                          discardOne(key);
                        }}
                        className="text-faint hover:text-danger"
                      >
                        ×
                      </button>
                    </span>
                  );
                })}
              </>
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
