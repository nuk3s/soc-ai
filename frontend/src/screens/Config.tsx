import { Key, ShieldAlert, Users } from 'lucide-react';
import { Fragment, useEffect, useMemo, useState } from 'react';
import { ApplyBadge, SourceBadge } from '../components/Badges';
import { NumberField, Select, Toggle } from '../components/Controls';
import { ManagedList } from '../components/ManagedList';
import { SectionTitle } from '../components/Panel';
import { ErrorState, LoadingState, Spinner } from '../components/States';
import { addInternalIdentifier, createUser, getConfig, getDiscoveryScan, getInternalIdentifiers, listDangerSettings, listUsers, mintToken, removeIdentifier, resetUserPassword, revokeToken, saveDangerSetting, setIdentifierActive, setSetting, setUserRole, startDiscoveryScan, testConnection, toggleUserDisabled } from '../lib/api';
import type { IdentifierKind, InternalIdentifiers } from '../lib/api';
import { useAsync } from '../lib/useAsync';
import type { AdminUser, ConnTestResult, DangerSetting, Setting } from '../lib/types';
import { ConfigNav } from './ConfigNav';

/** Slugify a section title into a stable DOM id / anchor fragment. */
function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
}

export function Config() {
  const [nonce, setNonce] = useState(0);
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

  const [toggles, setToggles] = useState<Record<string, boolean>>({});
  const [minted, setMinted] = useState('');
  const [saveMsg, setSaveMsg] = useState('');

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

  // ── Left-nav section model ─────────────────────────────────────────────────
  // One nav entry per settings group, with the standalone sections appended.
  // To keep nav order == visual order, Internal identifiers is spliced in right
  // after the Discovery group (mirrors the in-page reorder below).
  const SECTIONS = useMemo(() => {
    const groupEntries: { id: string; label: string }[] = [];
    for (const g of data?.groups ?? []) {
      groupEntries.push({ id: slug(g.title), label: g.title });
      if (g.title === 'Discovery') {
        groupEntries.push({ id: 'internal-identifiers', label: 'Internal identifiers' });
      }
    }
    return [
      ...groupEntries,
      { id: 'users', label: 'Users' },
      { id: 'api-tokens', label: 'API tokens' },
      { id: 'diagnostics', label: 'Diagnostics' },
      { id: 'danger-zone', label: 'Danger Zone' },
    ];
  }, [data?.groups]);

  // Active-section highlight via IntersectionObserver. root:null (viewport) is
  // correct here: the AppShell scroll container scrolls within the viewport, and
  // config is the only thing in that scroll area. rootMargin -65% makes the
  // active section the one near the top third of the view.
  const [activeId, setActiveId] = useState('');
  useEffect(() => {
    const ids = SECTIONS.map((s) => s.id);
    const els = ids
      .map((id) => document.getElementById(id))
      .filter((el): el is HTMLElement => el != null);
    if (!els.length) return;
    const obs = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActiveId(visible[0].target.id);
      },
      { rootMargin: '0px 0px -65% 0px', threshold: 0 },
    );
    els.forEach((el) => obs.observe(el));
    return () => obs.disconnect();
  }, [SECTIONS, nonce, identNonce]);

  // Wrap a mutation so any error surfaces inline and the list refetches on success.
  const identMutation = (p: Promise<unknown>) => {
    setIdentError('');
    p.then(refetchIdents).catch((e: unknown) =>
      setIdentError(e instanceof Error ? e.message : 'Action failed'),
    );
  };

  const runScanNow = async () => {
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

  // Derived: current value of the auto-ack toggle (local state takes precedence).
  const autoAckEnabled = (s: Setting | undefined) => {
    if (!s) return false;
    return toggles['auto_ack_fp_enabled'] !== undefined
      ? toggles['auto_ack_fp_enabled']
      : (s.value as boolean);
  };

  if (loading) return <div className="p-6"><LoadingState label="Loading settings…" /></div>;
  if (error) return <div className="p-6"><ErrorState error={error} /></div>;
  if (!data) return null;

  const toggleValue = (s: Setting) =>
    toggles[s.key] !== undefined ? toggles[s.key] : (s.value as boolean);

  const save = (key: string, value: string) => {
    setSaveMsg('');
    setSetting(key, value)
      .then((r) => setSaveMsg(r.restart_required ? `${key} saved — restart required` : `${key} saved`))
      .catch((e) => setSaveMsg(`${key}: ${e?.message ?? e}`));
  };

  const renderControl = (s: Setting) => {
    if (s.type === 'toggle') {
      return (
        <Toggle
          on={toggleValue(s)}
          onChange={(next) => {
            setToggles((t) => ({ ...t, [s.key]: next }));
            save(s.key, String(next));
          }}
          label={s.key}
        />
      );
    }
    if (s.type === 'number') {
      // The auto-ack threshold is only meaningful when the toggle is on.
      const isAutoAckThreshold = s.key === 'auto_ack_fp_threshold';
      const thresholdEnabled = !isAutoAckThreshold || autoAckEnabled(
        data?.groups.flatMap((g) => g.items).find((i) => i.key === 'auto_ack_fp_enabled')
      );
      return (
        <div style={isAutoAckThreshold && !thresholdEnabled ? { opacity: 0.4, pointerEvents: 'none' } : undefined}>
          <NumberField value={s.value as number} bounds={s.bounds} onChange={(v) => save(s.key, String(v))} />
        </div>
      );
    }
    if (s.type === 'select') {
      return <Select value={s.value as string} options={s.options} onChange={(v) => save(s.key, v)} />;
    }
    return (
      <input
        defaultValue={String(s.value)}
        onBlur={(e) => save(s.key, e.target.value)}
        className="w-[200px] rounded-control border border-border-input bg-bg px-3 py-1.5 font-mono text-[12.5px] text-text outline-none focus:border-accent"
      />
    );
  };

  const handleDangerSave = async (key: string) => {
    if (dangerConfirm !== key) return;
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
    <div id="internal-identifiers" className="mb-[22px] scroll-mt-6">
      <SectionTitle
        right={
          <div className="flex items-center gap-2">
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
        Internal identifiers
      </SectionTitle>
      <div className="mb-2.5 text-[12px] text-dim">
        Redaction identifiers learned from your data and confirmed here — internal domain suffixes
        and bare hostnames are stripped from payloads before any cloud second opinion. On = soc-ai
        uses this to redact and classify; off = ignored. Reserved defaults are always on.
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
                onAdd={(value) => identMutation(addInternalIdentifier(kind, value))}
                onSetActive={(id, active) => identMutation(setIdentifierActive(id, active))}
                onRemove={(id) => identMutation(removeIdentifier(id))}
              />
            </div>
          );
        })
      ) : null}
    </div>
  );

  return (
    <div className="mx-auto flex max-w-workstation gap-6 px-[22px] pb-[60px] pt-5">
      <aside className="hidden w-[180px] flex-none lg:block">
        <ConfigNav sections={SECTIONS} activeId={activeId} />
      </aside>
      <div className="min-w-0 max-w-permalink flex-1">
      <div className="text-[20px] font-semibold tracking-[-.015em]">Config</div>
      <div className="mb-[18px] mt-0.5 text-[13px] text-dim">
        Runtime settings · users · API tokens. Source badges show whether a value is set in the database or pinned by an
        environment variable.
      </div>

      {saveMsg && (
        <div className="mb-3 rounded-control border border-border-2 bg-surface-1 px-3 py-2 font-mono text-[12px] text-dim">
          {saveMsg}
        </div>
      )}

      {/* settings groups — Internal identifiers is interleaved right after the
          Discovery group so it sits visually next to discovery tuning. */}
      {data.groups.map((g) => (
        <Fragment key={g.title}>
          <div id={slug(g.title)} className="mb-[22px] scroll-mt-6">
            <SectionTitle>{g.title}</SectionTitle>
            <div className="overflow-hidden rounded-card border border-border bg-surface-1">
              {g.items.map((s) => (
                <div key={s.key} className="flex items-center gap-3.5 border-b border-border-faint px-[15px] py-[13px]">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-[12.5px] font-semibold text-text-2">{s.key}</span>
                      <SourceBadge source={s.source} />
                      <ApplyBadge apply={s.apply} />
                    </div>
                    <div className="mt-1 text-[12px] text-dim">{s.help}</div>
                  </div>
                  <div className="flex-none">{renderControl(s)}</div>
                </div>
              ))}
            </div>
          </div>
          {g.title === 'Discovery' && internalIdentifiersSection}
        </Fragment>
      ))}

      {/* Users */}
      <div id="users" className="mb-[22px] scroll-mt-6">
        <SectionTitle right={<span className="text-faint"><Users size={14} /></span>}>
          Users
        </SectionTitle>

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
                    onClick={() =>
                      resetUserPassword(u.id).then((r) => {
                        setResetPw({ id: u.id, password: r.password });
                        setNonce((n) => n + 1);
                      })
                    }
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
      </div>

      {/* API tokens */}
      <div id="api-tokens" className="mb-[22px] scroll-mt-6">
        <SectionTitle
          right={
            <button
              onClick={() => mintToken().then((t) => { setMinted(t); setNonce((n) => n + 1); })}
              className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent"
            >
              + Mint token
            </button>
          }
        >
          API tokens
        </SectionTitle>

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
            <div key={tk.name} className="flex items-center gap-3 border-b border-border-faint px-[15px] py-3">
              <span className="text-faint"><Key size={15} /></span>
              <div className="flex-1">
                <div className="text-[13px] font-semibold">{tk.name}</div>
                <div className="mt-0.5 font-mono text-[11.5px] text-faint">
                  {tk.prefix} · created {tk.created} · last used {tk.used}
                </div>
              </div>
              <button
                onClick={() => revokeToken(tk.id).then(() => setNonce((n) => n + 1))}
                className="rounded-[7px] border px-[11px] py-[5px] text-[11.5px] font-semibold text-danger hover:bg-[rgba(240,68,56,.12)]"
                style={{ borderColor: 'rgba(240,68,56,.3)' }}
              >
                Revoke
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Diagnostics */}
      <div id="diagnostics" className="mb-[22px] scroll-mt-6">
        <SectionTitle>Diagnostics</SectionTitle>
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
      </div>

      {/* Danger Zone */}
      <div
        id="danger-zone"
        className="overflow-hidden rounded-card border scroll-mt-6"
        style={{
          borderColor: 'rgba(240,68,56,.35)',
          background: 'linear-gradient(180deg,rgba(240,68,56,.05),rgba(11,14,19,0) 60%),#0b0e13',
        }}
      >
        {/* Header */}
        <div
          className="flex items-center gap-[9px] border-b border-[rgba(240,68,56,.2)] px-4 py-[13px]"
          style={{ background: 'rgba(240,68,56,.06)' }}
        >
          <ShieldAlert size={15} className="text-[#f04438]" />
          <span className="text-[13px] font-semibold text-[#f04438]">Danger Zone</span>
          <span className="ml-auto text-[11px] text-text-muted">All changes require restart</span>
        </div>

        {/* Settings rows */}
        {dangerLoading ? (
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
      </div>
    </div>
  );
}
