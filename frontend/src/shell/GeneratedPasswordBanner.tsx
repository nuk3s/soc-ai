import { Key } from 'lucide-react';
import { useRef, useState } from 'react';
import { ChangePasswordModal } from './ChangePasswordModal';
import { useSession } from './Session';

/** The sessionStorage key of "Remind me later". A new browser session shows
 *  the banner again. */
export const PASSWORD_REMINDER_KEY = 'soc-ai:generated-password-remind-later';

function remindLater(): boolean {
  try {
    return window.sessionStorage.getItem(PASSWORD_REMINDER_KEY) === '1';
  } catch {
    return false;
  }
}

/**
 * The shell banner for the generated admin password (H1-D5, H1-I1).
 *
 * GET /me says when the signed-in account still uses the password soc-ai
 * generated at the first start. That password sits in a plaintext file on the
 * server. Settings > Users showed a banner, and the operator does not open
 * that page every day, so production kept the generated password. This
 * banner shows on every page until the password changes.
 *
 * It trusts the server flag, which only the bootstrap admin account can
 * carry. It needs a user row: with sign-in off there is no password to
 * change. "Remind me later" hides it for the browser session only.
 */
export function GeneratedPasswordBanner() {
  const { me, refresh } = useSession();
  const [later, setLater] = useState(remindLater);
  const [open, setOpen] = useState(false);
  const buttonRef = useRef<HTMLButtonElement>(null);

  const generated = !!me && me.signed_in !== false && me.password_is_generated === true;
  if (!generated || (later && !open)) return null;

  const hideForSession = () => {
    try {
      window.sessionStorage.setItem(PASSWORD_REMINDER_KEY, '1');
    } catch {
      // No storage: the banner hides until the next page load.
    }
    setLater(true);
  };

  return (
    <>
      {!later && (
        <div
          data-testid="generated-password-shell-banner"
          role="status"
          className="flex flex-none flex-wrap items-center gap-x-3 gap-y-1 border-b px-[22px] py-1.5 text-[12.5px]"
          style={{ borderColor: 'rgba(245,166,35,.3)', background: 'rgba(245,166,35,.07)' }}
        >
          <span className="flex text-warn">
            <Key size={14} />
          </span>
          <span className="min-w-0 flex-1 text-text-2">
            This account still uses the generated password. Change it now.
          </span>
          <button
            ref={buttonRef}
            type="button"
            onClick={() => setOpen(true)}
            className="flex-none rounded-[7px] border border-warn px-[10px] py-[3px] text-[11.5px] font-semibold text-warn hover:bg-[rgba(245,166,35,.1)]"
          >
            Change password
          </button>
          <button
            type="button"
            onClick={hideForSession}
            className="flex-none text-[11.5px] font-semibold text-dim hover:text-text"
          >
            Remind me later
          </button>
        </div>
      )}
      {open && (
        <ChangePasswordModal
          open
          returnFocusRef={buttonRef}
          onClose={() => {
            setOpen(false);
            // The change sends PASSWORD_CHANGED_EVENT too. A read here also
            // covers a server that changed the flag another way.
            refresh();
          }}
        />
      )}
    </>
  );
}
