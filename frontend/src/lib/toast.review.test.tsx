import { act, fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { ToastProvider, useToast } from './toast';

function Trigger({ opts }: { opts: Parameters<ReturnType<typeof useToast>['toast']>[0] }) {
  const { toast } = useToast();
  return (
    <button type="button" onClick={() => toast(opts)}>
      go
    </button>
  );
}

describe('toast (2026-07-31 visual pass)', () => {
  it('shows a toast and removes it on dismiss', () => {
    render(
      <ToastProvider>
        <Trigger opts={{ message: 'acknowledged 12 alerts', tone: 'success' }} />
      </ToastProvider>,
    );
    fireEvent.click(screen.getByText('go'));
    expect(screen.queryByText('acknowledged 12 alerts')).toBeTruthy();
    fireEvent.click(screen.getByLabelText('Dismiss notification'));
    expect(screen.queryByText('acknowledged 12 alerts')).toBeNull();
  });

  it('auto-dismisses a non-error toast after its duration, errors persist', () => {
    vi.useFakeTimers();
    try {
      render(
        <ToastProvider>
          <Trigger opts={{ message: 'triage complete', tone: 'info' }} />
          <Trigger opts={{ message: 'gateway error', tone: 'danger' }} />
        </ToastProvider>,
      );
      const [info, danger] = screen.getAllByText('go');
      act(() => fireEvent.click(info));
      act(() => fireEvent.click(danger));
      expect(screen.queryByText('triage complete')).toBeTruthy();
      expect(screen.queryByText('gateway error')).toBeTruthy();
      act(() => vi.advanceTimersByTime(6000));
      expect(screen.queryByText('triage complete')).toBeNull(); // info auto-dismissed
      expect(screen.queryByText('gateway error')).toBeTruthy(); // danger persists
    } finally {
      vi.useRealTimers();
    }
  });
});
