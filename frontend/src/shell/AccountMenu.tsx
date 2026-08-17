import { ChevronUp, KeyRound, LogOut } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { RoleChip } from '../components/Badges';
import { setMyStatus, signOut } from '../lib/api';
import type { Me } from '../lib/types';
import { ChangePasswordModal } from './ChangePasswordModal';
import { useShell } from './ShellContext';

function initials(username: string): string {
  const parts = username.trim().split(/[\s._-]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  return username.slice(0, 2).toUpperCase();
}

interface Props {
  me: Me;
  /** Lift the status back to the sidebar so the collapsed avatar stays in step. */
  onMe: (next: Me) => void;
}

/**
 * The account surface, opened from the sidebar avatar.
 *
 * It exists because the old footer row was three disconnected affordances: an
 * inert avatar, a click-to-edit status, and a logout icon — and both the status
 * and the logout icon were rendered inside `{!collapsed && …}`, so collapsing
 * the rail removed the only way to sign out. Everything account-shaped now
 * lives in one menu that opens in BOTH sidebar states, and the role finally
 * appears as text instead of a hover `title`.
 *
 * The popover is `position: fixed`, anchored off the trigger's rect: the
 * sidebar is an `overflow-hidden` flex column, so an absolutely-positioned
 * child would be clipped at the 64px rail.
 */
export function AccountMenu({ me, onMe }: Props) {
  const { collapsed } = useShell();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [pwOpen, setPwOpen] = useState(false);
  const [anchor, setAnchor] = useState({ left: 12, bottom: 12 });
  const [editingStatus, setEditingStatus] = useState(false);
  const [statusDraft, setStatusDraft] = useState('');
  const triggerRef = useRef<HTMLButtonElement>(null);
  const statusRef = useRef<HTMLInputElement>(null);

  // Escape closes — but while the status field is open it cancels that edit
  // first, so one keystroke never discards the draft AND the menu together.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      if (editingStatus) {
        setEditingStatus(false);
        setStatusDraft('');
        return;
      }
      setOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, editingStatus]);

  function toggle() {
    if (!open) {
      const r = triggerRef.current?.getBoundingClientRect();
      if (r) {
        // Opens UPWARD: the trigger sits at the bottom of the sidebar.
        setAnchor({
          left: Math.max(8, r.left),
          bottom: Math.max(8, window.innerHeight - r.top + 8),
        });
      }
      setEditingStatus(false);
    }
    setOpen((o) => !o);
  }

  function startEdit() {
    setStatusDraft(me.status);
    setEditingStatus(true);
    setTimeout(() => statusRef.current?.focus(), 0);
  }

  function commitEdit() {
    const trimmed = statusDraft.trim().slice(0, 64);
    setEditingStatus(false);
    setMyStatus(trimmed)
      .then((r) => onMe({ ...me, status: r.status }))
      .catch(() => {
        /* silently leave the old value — same as the row this replaced */
      });
  }

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        onClick={toggle}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Account menu — signed in as ${me.username}`}
        className="flex w-full items-center gap-[9px] rounded-control border-t border-border px-1 pb-1 pt-2.5 text-left outline-none hover:bg-surface-3 focus-visible:ring-1 focus-visible:ring-accent"
        style={{ justifyContent: collapsed ? 'center' : 'flex-start' }}
      >
        <div
          className="flex h-7 w-7 flex-none items-center justify-center rounded-full border border-border-input text-[11px] font-semibold text-[#b9c2cf]"
          style={{ background: 'linear-gradient(135deg,#2c3340,#1a1f28)' }}
        >
          {initials(me.username)}
        </div>
        {!collapsed && (
          <>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-[12.5px] font-semibold text-text">
                {me.username}
              </span>
              <span className="block truncate text-[10.5px] text-faint">
                {me.status || me.role}
              </span>
            </span>
            <span className="flex flex-none text-faint">
              <ChevronUp size={13} />
            </span>
          </>
        )}
      </button>

      {open && (
        <>
          {/* click-catcher, the Topbar dropdown pattern */}
          <div onClick={() => setOpen(false)} className="fixed inset-0 z-[45]" />
          <div
            role="menu"
            aria-label="Account"
            className="fixed z-[46] w-[236px] animate-fadeUp overflow-hidden rounded-panel border border-border-input bg-surface-card shadow-dropdown"
            style={{ left: anchor.left, bottom: anchor.bottom }}
          >
            <div className="border-b border-border-2 px-3.5 py-3">
              <div className="truncate text-[13px] font-semibold text-text">{me.username}</div>
              <div className="mt-1.5 flex items-center gap-1.5">
                <RoleChip role={me.role} />
                <span className="text-[11px] text-faint">role</span>
              </div>
            </div>

            <div className="border-b border-border-2 px-3.5 py-2.5">
              <div className="pb-1 text-[10px] font-semibold uppercase tracking-[.06em] text-faint">
                Status
              </div>
              {editingStatus ? (
                <input
                  ref={statusRef}
                  value={statusDraft}
                  maxLength={64}
                  aria-label="Status"
                  onChange={(e) => setStatusDraft(e.target.value)}
                  onBlur={commitEdit}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') commitEdit();
                  }}
                  className="w-full rounded-control border border-border-input bg-bg px-2 py-1 text-[12px] text-text outline-none focus:border-accent"
                  placeholder="Set status…"
                />
              ) : (
                <button
                  type="button"
                  onClick={startEdit}
                  aria-label={me.status ? `Status: ${me.status}. Set status` : 'Set status'}
                  className="w-full truncate rounded-control px-0 py-px text-left text-[12px] text-dim outline-none hover:text-text focus-visible:ring-1 focus-visible:ring-accent"
                >
                  {me.status || <span className="italic text-faint">Set status…</span>}
                </button>
              )}
            </div>

            <div className="p-1.5">
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setOpen(false);
                  setPwOpen(true);
                }}
                className="flex w-full items-center gap-2.5 rounded-control px-[9px] py-2 text-left text-[12.5px] text-text-2 outline-none hover:bg-[#141b25] hover:text-text focus-visible:ring-1 focus-visible:ring-accent"
              >
                <span className="flex w-[15px] flex-none justify-center text-faint">
                  <KeyRound size={14} />
                </span>
                Change password
              </button>
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setOpen(false);
                  signOut(navigate);
                }}
                className="flex w-full items-center gap-2.5 rounded-control px-[9px] py-2 text-left text-[12.5px] text-text-2 outline-none hover:bg-[#141b25] hover:text-text focus-visible:ring-1 focus-visible:ring-accent"
              >
                <span className="flex w-[15px] flex-none justify-center text-faint">
                  <LogOut size={14} />
                </span>
                Sign out
              </button>
            </div>
          </div>
        </>
      )}

      {/* The menu item that opens this unmounts with the menu in the same
          commit, so the dialog has no live opener to hand focus back to — name
          the avatar trigger, which outlives both. */}
      <ChangePasswordModal
        open={pwOpen}
        onClose={() => setPwOpen(false)}
        returnFocusRef={triggerRef}
      />
    </>
  );
}
