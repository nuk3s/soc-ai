import { useState } from 'react';
import { ErrorState, LoadingState } from '../components/States';
import { type ApiKeyField, clearApiKey, getApiKeys, saveApiKey } from '../lib/api';
import { useAsync } from '../lib/useAsync';

/**
 * API keys — write-only entry for the opt-in online-enrichment provider keys.
 * Values are Fernet-encrypted at rest, never returned to the client, and applied
 * live (no restart). Sits next to Data sources in the config console.
 */
export function ApiKeysPanel() {
  const [reload, setReload] = useState(0);
  const { data, loading, error } = useAsync(getApiKeys, [reload]);
  const [editKey, setEditKey] = useState<string | null>(null);
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ key: string; text: string; ok: boolean } | null>(null);

  const keys: ApiKeyField[] = data ?? [];
  const cancel = () => {
    setEditKey(null);
    setValue('');
  };

  const save = async (k: string) => {
    if (!value.trim()) return;
    setBusy(true);
    setMsg(null);
    try {
      await saveApiKey(k, value.trim());
      setMsg({ key: k, text: 'Saved — applied live', ok: true });
      cancel();
      setReload((n) => n + 1);
    } catch (e) {
      setMsg({ key: k, text: e instanceof Error ? e.message : 'Save failed', ok: false });
    } finally {
      setBusy(false);
    }
  };

  const clear = async (k: string) => {
    setBusy(true);
    setMsg(null);
    try {
      await clearApiKey(k);
      setMsg({ key: k, text: 'Cleared', ok: true });
      cancel();
      setReload((n) => n + 1);
    } catch (e) {
      setMsg({ key: k, text: e instanceof Error ? e.message : 'Clear failed', ok: false });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div id="api-keys" className="mb-[22px] scroll-mt-6">
      <div className="mb-1 text-[15px] font-semibold">API keys</div>
      <div className="mb-3 text-[12.5px] leading-[1.5] text-dim">
        Provider keys for the opt-in online enrichment tools. Stored encrypted, write-only (never
        shown again) and applied live — no restart. Turn on the master switch under "Online
        enrichment" to actually use them.
      </div>
      <div className="overflow-hidden rounded-card border border-border bg-surface-1">
        {loading && !data && <LoadingState />}
        {error && (
          <div className="p-3">
            <ErrorState error={error} />
          </div>
        )}
        {keys.map((k) => {
          const editing = editKey === k.key;
          const m = msg?.key === k.key ? msg : null;
          return (
            <div key={k.key} className="border-b border-border-faint px-[15px] py-3 last:border-0">
              <div className="flex items-center gap-3">
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-medium">{k.label}</div>
                  <div className="mt-0.5 text-[11.5px] leading-[1.4] text-faint">{k.help}</div>
                </div>
                <span
                  className="flex-none rounded px-1.5 py-0.5 text-[10px] font-semibold"
                  style={{
                    background: k.isSet ? 'rgba(63,185,80,.15)' : 'rgba(139,148,163,.12)',
                    color: k.isSet ? '#3fb950' : '#8b94a3',
                  }}
                >
                  {k.isSet ? 'Set' : 'Not set'}
                </span>
                {k.source !== 'unset' && (
                  <span className="flex-none rounded border border-border px-1.5 py-0.5 text-[10px] font-semibold text-faint">
                    {k.source}
                  </span>
                )}
                {!editing && (
                  <button
                    onClick={() => {
                      setEditKey(k.key);
                      setValue('');
                      setMsg(null);
                    }}
                    className="flex-none rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent"
                  >
                    {k.isSet ? 'Replace' : 'Set'}
                  </button>
                )}
                {!editing && k.isSet && (
                  <button
                    onClick={() => {
                      void clear(k.key);
                    }}
                    disabled={busy}
                    className="flex-none rounded-[7px] border px-[11px] py-[5px] text-[11.5px] font-semibold text-danger hover:bg-[rgba(240,68,56,.12)] disabled:opacity-50"
                    style={{ borderColor: 'rgba(240,68,56,.3)' }}
                  >
                    Clear
                  </button>
                )}
              </div>
              {editing && (
                <div className="mt-2.5 flex flex-wrap items-center gap-2">
                  <input
                    type="password"
                    autoComplete="new-password"
                    value={value}
                    onChange={(e) => setValue(e.target.value)}
                    placeholder="Paste key — write-only"
                    className="w-[260px] rounded-control border border-border-input bg-bg px-3 py-1.5 font-mono text-[12.5px] text-text outline-none focus:border-accent"
                  />
                  <button
                    onClick={() => {
                      void save(k.key);
                    }}
                    disabled={busy || !value.trim()}
                    className="rounded-[7px] border border-accent px-[11px] py-1.5 text-[12px] font-semibold text-accent disabled:opacity-50"
                  >
                    {busy ? 'Saving…' : 'Save'}
                  </button>
                  <button
                    onClick={cancel}
                    className="rounded-[7px] border border-border-strong px-[11px] py-1.5 text-[12px] font-semibold text-dim hover:text-text"
                  >
                    Cancel
                  </button>
                </div>
              )}
              {m && (
                <div className="mt-1.5 text-[11.5px]" style={{ color: m.ok ? '#3fb950' : '#f04438' }}>
                  {m.text}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
