import { AlertTriangle, CheckCircle2, Info, X } from 'lucide-react';
import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';

export type ToastTone = 'success' | 'danger' | 'info';

export interface ToastOptions {
  message: string;
  tone?: ToastTone;
  /** Optional single action, e.g. "1 failed — view". Dismisses the toast when clicked. */
  action?: { label: string; onClick: () => void };
  /**
   * ms before auto-dismiss; 0 = persist until dismissed. Defaults: success/info
   * 6s (glanceable), danger 0 (an error should not vanish before it's read).
   */
  duration?: number;
}

interface Toast {
  id: number;
  tone: ToastTone;
  message: string;
  action?: ToastOptions['action'];
}

interface ToastApi {
  /** Push a toast. Global, bottom-right, newest on top, max 3 stacked. */
  toast: (opts: ToastOptions) => void;
}

const Ctx = createContext<ToastApi | null>(null);

/**
 * App-wide toaster. Results and one-shot notices go here (the Alerts header used
 * to grow a stack of dismissible result strips instead); in-progress work stays
 * inline on its screen, and persistent context stays bound to what it explains.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const idRef = useRef(0);

  const dismiss = useCallback((id: number) => {
    setToasts((cur) => cur.filter((t) => t.id !== id));
  }, []);

  const toast = useCallback(
    (opts: ToastOptions) => {
      const tone = opts.tone ?? 'info';
      const id = (idRef.current += 1);
      // Newest on top, capped at 3 — a burst never buries the screen.
      setToasts((cur) => [{ id, tone, message: opts.message, action: opts.action }, ...cur].slice(0, 3));
      const duration = opts.duration ?? (tone === 'danger' ? 0 : 6000);
      if (duration > 0) setTimeout(() => dismiss(id), duration);
    },
    [dismiss],
  );

  const api = useMemo(() => ({ toast }), [toast]);

  return (
    <Ctx.Provider value={api}>
      {children}
      <Toaster toasts={toasts} onDismiss={dismiss} />
    </Ctx.Provider>
  );
}

/**
 * Returns the toast API. Outside a ToastProvider (e.g. a component rendered in
 * isolation by a unit test) it's a no-op so callers never crash.
 */
export function useToast(): ToastApi {
  return useContext(Ctx) ?? NOOP;
}
const NOOP: ToastApi = { toast: () => {} };

const TONE: Record<ToastTone, { Icon: typeof Info; tint: string; wash: string }> = {
  success: { Icon: CheckCircle2, tint: 'text-success', wash: 'rgba(63,185,80,.10)' },
  danger: { Icon: AlertTriangle, tint: 'text-danger', wash: 'rgba(240,68,56,.10)' },
  info: { Icon: Info, tint: 'text-accent', wash: 'rgba(75,139,245,.08)' },
};

function Toaster({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  if (toasts.length === 0) return null;
  return (
    <div
      role="region"
      aria-label="Notifications"
      // Sits just above the deploy-update notice; pointer-events-none so it never
      // blocks the content beneath, re-enabled per toast.
      className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[360px] max-w-[calc(100vw-2rem)] flex-col gap-2"
    >
      {toasts.map((t) => {
        const meta = TONE[t.tone];
        return (
          <div
            key={t.id}
            role="status"
            className="pointer-events-auto flex animate-slideIn items-start gap-2.5 rounded-card border border-border-2 px-3.5 py-2.5 shadow-dropdown"
            style={{ background: meta.wash }}
          >
            <span className={`mt-px flex-none ${meta.tint}`}>
              <meta.Icon size={15} />
            </span>
            <div className="min-w-0 flex-1 text-[12.5px] leading-[1.5] text-text">{t.message}</div>
            {t.action && (
              <button
                onClick={() => {
                  t.action!.onClick();
                  onDismiss(t.id);
                }}
                className="flex-none text-[12px] font-semibold text-accent hover:underline"
              >
                {t.action.label}
              </button>
            )}
            <button
              onClick={() => onDismiss(t.id)}
              aria-label="Dismiss notification"
              className="flex-none text-dim hover:text-text"
            >
              <X size={14} />
            </button>
          </div>
        );
      })}
    </div>
  );
}
