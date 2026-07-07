import { useEffect, useState } from 'react';
import { Bell } from 'lucide-react';
import { CollapseChevron } from '../components/Panel';
import {
  clearNotifyWebhook,
  getNotifyWebhook,
  saveNotifyWebhook,
  testNotifyWebhook,
} from '../lib/api';
import type { NotifyWebhookStatus } from '../lib/api';

/**
 * Notifications — the outbound-webhook secret + a "Send test" validation.
 *
 * The master toggle, per-trigger toggles, format select, and TP threshold are
 * ordinary settings rendered in the "Notifications" settings group above this
 * panel. This panel owns the WEBHOOK URL (a write-only, Fernet-encrypted secret)
 * and the Test button.
 *
 * EGRESS: everything here is inert until the operator both sets a webhook URL AND
 * flips the master toggle on. The Test button is the one deliberate exception — it
 * sends a canned, synthetic event (no internal data) so the destination can be
 * validated BEFORE routing is enabled. It requires a URL but not the master
 * toggle.
 */
export function NotificationsPanel({
  collapsed = false,
  onToggleCollapse,
}: {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
} = {}) {
  const [status, setStatus] = useState<NotifyWebhookStatus | null>(null);
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);
  const [testResult, setTestResult] = useState<{ ok: boolean; detail: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [reload, setReload] = useState(0);

  useEffect(() => {
    let active = true;
    getNotifyWebhook()
      .then((r) => {
        if (active) setStatus(r);
      })
      .catch(() => {
        if (active) setStatus(null);
      });
    return () => {
      active = false;
    };
  }, [reload]);

  const cancel = () => {
    setEditing(false);
    setValue('');
  };

  const save = async () => {
    if (!value.trim()) return;
    setBusy(true);
    setMsg(null);
    try {
      await saveNotifyWebhook(value.trim());
      setMsg({ text: 'Saved — applied live', ok: true });
      cancel();
      setReload((n) => n + 1);
    } catch (e) {
      setMsg({ text: e instanceof Error ? e.message : 'Save failed', ok: false });
    } finally {
      setBusy(false);
    }
  };

  const clear = async () => {
    setBusy(true);
    setMsg(null);
    try {
      await clearNotifyWebhook();
      setMsg({ text: 'Cleared', ok: true });
      cancel();
      setTestResult(null);
      setReload((n) => n + 1);
    } catch (e) {
      setMsg({ text: e instanceof Error ? e.message : 'Clear failed', ok: false });
    } finally {
      setBusy(false);
    }
  };

  const sendTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const r = await testNotifyWebhook();
      setTestResult({ ok: r.ok, detail: r.detail });
    } catch (e) {
      setTestResult({ ok: false, detail: e instanceof Error ? e.message : 'Test failed' });
    } finally {
      setTesting(false);
    }
  };

  const isSet = !!status?.isSet;

  return (
    <div id="notifications-webhook" className="mb-[22px] scroll-mt-6">
      <div className="mb-1 flex items-center gap-2">
        <Bell size={14} className="text-faint" />
        <div className="text-[15px] font-semibold">Notification webhook</div>
        {onToggleCollapse && (
          <CollapseChevron
            collapsed={collapsed}
            onToggle={onToggleCollapse}
            label="Toggle notification webhook"
          />
        )}
      </div>
      {!collapsed && (
        <>
          <div className="mb-3 text-[12.5px] leading-[1.5] text-dim">
            The one outbound egress path in soc-ai. Stored encrypted, write-only (never shown again)
            and applied live. Nothing is sent until you set this URL <strong>and</strong> turn on
            "Notifications enabled" above. Use <strong>Send test</strong> to validate the destination
            first — it sends a synthetic message (no internal data) and does not require the master
            toggle.
          </div>
          <div className="overflow-hidden rounded-card border border-border bg-surface-1">
            <div className="border-b border-border-faint px-[15px] py-3 last:border-0">
              <div className="flex items-center gap-3">
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-medium">Webhook URL</div>
                  <div className="mt-0.5 text-[11.5px] leading-[1.4] text-faint">
                    Destination for notifications (generic JSON, Slack, or Matrix — pick the format
                    above).
                  </div>
                </div>
                <span
                  className="flex-none rounded px-1.5 py-0.5 text-[10px] font-semibold"
                  style={{
                    background: isSet ? 'rgba(63,185,80,.15)' : 'rgba(139,148,163,.12)',
                    color: isSet ? '#3fb950' : '#8b94a3',
                  }}
                >
                  {isSet ? 'Set' : 'Not set'}
                </span>
                {status && status.source !== 'unset' && (
                  <span className="flex-none rounded border border-border px-1.5 py-0.5 text-[10px] font-semibold text-faint">
                    {status.source}
                  </span>
                )}
                {!editing && (
                  <button
                    onClick={() => {
                      setEditing(true);
                      setValue('');
                      setMsg(null);
                    }}
                    className="flex-none rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent"
                  >
                    {isSet ? 'Replace' : 'Set'}
                  </button>
                )}
                {!editing && isSet && (
                  <button
                    onClick={() => {
                      void clear();
                    }}
                    disabled={busy}
                    className="flex-none rounded-[7px] border px-[11px] py-[5px] text-[11.5px] font-semibold text-danger hover:bg-[rgba(240,68,56,.12)] disabled:opacity-50"
                    style={{ borderColor: 'rgba(240,68,56,.3)' }}
                  >
                    Clear
                  </button>
                )}
                {!editing && isSet && (
                  <button
                    onClick={() => {
                      void sendTest();
                    }}
                    disabled={testing}
                    className="flex-none rounded-[7px] border border-accent px-[11px] py-[5px] text-[11.5px] font-semibold text-accent hover:bg-accent/15 disabled:opacity-50"
                  >
                    {testing ? 'Sending…' : 'Send test'}
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
                    placeholder="https://hooks.example.com/… — write-only"
                    className="w-[300px] rounded-control border border-border-input bg-bg px-3 py-1.5 font-mono text-[12.5px] text-text outline-none focus:border-accent"
                  />
                  <button
                    onClick={() => {
                      void save();
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
              {msg && (
                <div className="mt-1.5 text-[11.5px]" style={{ color: msg.ok ? '#3fb950' : '#f04438' }}>
                  {msg.text}
                </div>
              )}
              {testResult && (
                <div
                  className="mt-1.5 text-[11.5px]"
                  style={{ color: testResult.ok ? '#3fb950' : '#f04438' }}
                >
                  {testResult.ok ? '✓ ' : '✗ '}
                  {testResult.detail}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
