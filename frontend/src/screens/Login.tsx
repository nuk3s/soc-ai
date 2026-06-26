import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { login } from '../lib/api';
import { ScopeMark, Wordmark } from '../components/Logo';

export function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState('');

  const signIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setPending(true);
    try {
      await login(username, password);
      navigate('/alerts');
    } catch {
      setError('Invalid username or password');
    } finally {
      setPending(false);
    }
  };

  return (
    <div
      className="relative flex h-screen items-center justify-center"
      style={{
        background:
          'radial-gradient(900px 600px at 50% -10%,rgba(75,139,245,.10),transparent 60%),#080a0e',
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
          className="rounded-panel-lg border border-border-2 bg-surface-card p-7 shadow-login-card"
        >
          <div className="text-[19px] font-semibold tracking-[-.01em]">Sign in to console</div>
          <div className="mb-[22px] mt-[5px] text-[13px] text-dim">
            Self-hosted · Security Onion integration
          </div>

          <label className="mb-1.5 block text-[12px] font-medium text-dim" htmlFor="username">
            Username
          </label>
          <input
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
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
            className="mb-5 w-full rounded-control border border-border-input bg-bg px-3 py-2.5 text-[13.5px] text-text outline-none focus:border-accent"
          />

          {error && (
            <div className="mb-4 rounded-control border border-[rgba(240,68,56,.3)] bg-[rgba(240,68,56,.06)] px-3 py-2 text-[12.5px] text-danger">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={pending}
            className="w-full rounded-control bg-accent py-[11px] text-[14px] font-semibold text-white hover:bg-accent-deep disabled:opacity-60 disabled:cursor-not-allowed"
          >
            {pending ? 'Signing in…' : 'Sign in'}
          </button>

          <div className="mt-4 flex items-center gap-2 font-mono text-[11.5px] text-faint">
            <span className="h-1.5 w-1.5 animate-pulseDot rounded-full bg-success" />
            TLS 1.3 · self-hosted
          </div>
        </form>
      </div>
    </div>
  );
}
