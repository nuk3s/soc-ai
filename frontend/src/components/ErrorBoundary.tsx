import { AlertTriangle } from 'lucide-react';
import { Component } from 'react';
import type { ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * Last-resort render boundary. Without one, ANY render/lazy-import error
 * unmounts the entire React tree — a blank page until a hard refresh (bitten
 * for real by a deploy invalidating chunks under an open tab). One instance
 * wraps each Suspense boundary's children so a crashing route shows a card in
 * place while the shell (sidebar/topbar) stays mounted. Deliberately dumb: no
 * logging, no retry state machine — Reload is the recovery path.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  render(): ReactNode {
    if (!this.state.error) return this.props.children;
    return (
      <div className="flex min-h-[50vh] items-center justify-center px-4">
        <div className="flex max-w-[440px] flex-col items-center gap-2 rounded-card border border-[rgba(240,68,56,.3)] bg-[rgba(240,68,56,.05)] px-6 py-8 text-center">
          <span className="text-danger">
            <AlertTriangle size={20} />
          </span>
          <div className="text-[13.5px] font-semibold text-text">
            Something went wrong loading this page
          </div>
          <div className="break-words font-mono text-[11.5px] text-faint">
            {this.state.error.message}
          </div>
          <button
            onClick={() => window.location.reload()}
            className="mt-1 rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12px] font-semibold text-text hover:border-accent"
          >
            Reload
          </button>
        </div>
      </div>
    );
  }
}
