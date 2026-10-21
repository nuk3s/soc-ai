import { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { getAuthStatus, login, takePostLoginRedirect } from '../lib/api';
import { loginReasonLine, markSignedIn } from '../lib/loginReason';
import { DEMO_BANNER_H, DemoBanner, useDemoStatus } from '../lib/demo';
import { ScopeMark, Wordmark } from '../components/Logo';

export function Login() {
  const navigate = useNavigate();
  // Why the page shows: a session that ended, a sign out, or a deep link
  // (dogfood 2026-10-19, H1-D18).
  const reason = loginReasonLine(useLocation().search);
  // Login routes OUTSIDE AppShell, so it carries its own honesty banner —
  // demo mode does not force auth off, and the demo's FIRST screen must
  // already say the results are recorded. /demo-status is open (pre-auth).
  const demo = useDemoStatus();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState('');
  // false = this server runs with sign-in off. Every visitor has admin access
  // then, and a full form read as a gate that did not exist (dogfood
  // 2026-10-19, R1-D20). null = not known: the form shows, as before.
  const [authRequired, setAuthRequired] = useState<boolean | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  useEffect(() => {
    let live = true;
    getAuthStatus()
      .then((r) => {
        if (live) setAuthRequired(r.auth_required);
      })
      .catch(() => {
        /* unknown: keep the form */
      });
    return () => {
      live = false;
    };
  }, []);
  const showForm = authRequired !== false || formOpen;
  // The real transport of this page. A browser cannot read the TLS version,
  // so the line names the scheme only. It used to claim "TLS 1.3" with a
  // green dot over plain HTTP (dogfood 2026-10-19, H1-D3).
  const encrypted = typeof window !== 'undefined' && window.location.protocol === 'https:';

  const signIn = async (e: React.FormEvent) => {
    e.preventDefault();
    // The server answered an empty field with "username is empty. Send a
    // value. soc-ai got ''." (dogfood 2026-10-19, H1-D16).
    if (!username.trim()) {
      setError('Enter a username.');
      return;
    }
    if (!password) {
      setError('Enter your password.');
      return;
    }
    setError('');
    setPending(true);
    try {
      await login(username, password);
      // A later 401 then reads as an ended session, not a first visit.
      markSignedIn();
      // Where they were headed when the session expired, not where we'd like
      // them to start. A 401 on /app/hosts/198.51.100.5 bounced through here
      // and landed on the dashboard, throwing away the link the analyst had
      // actually followed — usually one someone else had sent them. `replace`
      // because the login screen is not a place to go Back to.
      navigate(takePostLoginRedirect() ?? '/dashboard', { replace: true });
    } catch (e) {
      // login() already returns a generic message on a real 401 and surfaces
      // the server's hint (e.g. rate-limit) or a network/cert error otherwise.
      setError(e instanceof Error ? e.message : 'The username or the password is wrong.');
    } finally {
      setPending(false);
    }
  };

  return (
    <>
      {demo && <DemoBanner />}
      <div
        className="relative flex h-screen items-center justify-center"
        style={{
          background:
            'radial-gradient(900px 600px at 50% -10%,rgba(75,139,245,.10),transparent 60%),#080a0e',
          ...(demo ? { height: `calc(100vh - ${DEMO_BANNER_H}px)` } : {}),
        }}
      >
        {/* faint grid texture, radial-masked */}
        <div
          className="absolute inset-0"
          style={{
            backgroundImage:
              'linear-gradient(rgba(255,255,255,.022) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.022) 1px,transparent 1px)',
            backgroundSize: '34px 34px',
            maskImage: 'radial-gradient(circle at 50% 35%,#000,transparent 75%)',
            WebkitMaskImage: 'radial-gradient(circle at 50% 35%,#000,transparent 75%)',
          }}
        />
        <div className="relative w-[380px] animate-fadeUp-slow">
          <div className="mb-[26px] flex items-center gap-[11px]">
            <ScopeMark size={34} glow />
            <Wordmark size={17} />
          </div>
          <form
            onSubmit={signIn}
            noValidate
            className="rounded-panel-lg border border-border-2 bg-surface-card p-7 shadow-login-card"
          >
            {!showForm ? (
              <>
                <div className="text-[19px] font-semibold tracking-[-.01em]">Sign-in is off</div>
                <div className="mb-[22px] mt-[5px] text-[13px] leading-[1.5] text-dim">
                  This server runs with authentication off. Every visitor has admin access. Sign in
                  with an account to create an API token or to manage users.
                </div>
                <button
                  type="button"
                  onClick={() => navigate(takePostLoginRedirect() ?? '/dashboard', { replace: true })}
                  className="w-full rounded-control bg-accent py-[11px] text-[14px] font-semibold text-white hover:bg-accent-deep"
                >
                  Open the console
                </button>
                <button
                  type="button"
                  onClick={() => setFormOpen(true)}
                  className="mt-2.5 w-full rounded-control border border-border-input py-[9px] text-[13px] font-semibold text-dim hover:border-border-strong hover:text-text"
                >
                  Sign in with an account
                </button>
              </>
            ) : (
            <>
            <div className="text-[19px] font-semibold tracking-[-.01em]">Sign in to the console</div>
            <div className="mb-[22px] mt-[5px] text-[13px] text-dim">
              Self-hosted · Security Onion integration
            </div>

            {reason && (
              <div
                data-testid="login-reason"
                role="status"
                className="mb-4 rounded-control border border-border-2 bg-surface-3 px-3 py-2 text-[12.5px] text-text-2"
              >
                {reason}
              </div>
            )}

            <label className="mb-1.5 block text-[12px] font-medium text-dim" htmlFor="username">
              Username
            </label>
            <input
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              // The first field takes the focus on load (dogfood 2026-10-19,
              // H1-D19).
              autoFocus
              required
              className="mb-3.5 w-full rounded-control border border-border-input bg-bg px-3 py-2.5 text-[13.5px] text-text outline-none focus:border-accent"
            />

            <label className="mb-1.5 block text-[12px] font-medium text-dim" htmlFor="password">
              Password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
              className="mb-5 w-full rounded-control border border-border-input bg-bg px-3 py-2.5 text-[13.5px] text-text outline-none focus:border-accent"
            />

            {error && (
              <div role="alert" className="mb-4 rounded-control border border-[rgba(240,68,56,.3)] bg-[rgba(240,68,56,.06)] px-3 py-2 text-[12.5px] text-danger">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={pending}
              className="w-full rounded-control bg-accent py-[11px] text-[14px] font-semibold text-white hover:bg-accent-deep disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {pending ? 'Signing in' : 'Sign in'}
            </button>
            </>
            )}

            <div
              data-testid="login-transport"
              className="mt-4 flex items-center gap-2 font-mono text-[11.5px] text-faint"
            >
              <span className={`h-1.5 w-1.5 rounded-full ${encrypted ? 'bg-success' : 'bg-warn'}`} />
              {encrypted ? 'HTTPS. The connection is encrypted.' : 'HTTP. The connection is not encrypted.'}
            </div>
          </form>
        </div>
      </div>
    </>
  );
}
