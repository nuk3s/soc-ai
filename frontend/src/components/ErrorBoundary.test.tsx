// The last-resort boundary: without it, any render/lazy error blanks the whole
// SPA. Pins both halves of the contract — transparent pass-through when
// healthy, and the reload card (message + working Reload) when a child throws.
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ErrorBoundary } from './ErrorBoundary';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('ErrorBoundary', () => {
  it('renders children untouched when nothing throws', () => {
    render(
      <ErrorBoundary>
        <div>healthy screen</div>
      </ErrorBoundary>,
    );
    expect(screen.getByText('healthy screen')).toBeInTheDocument();
    expect(screen.queryByText('Something went wrong loading this page')).toBeNull();
  });

  it('shows the reload card with the error message when a child throws; Reload reloads', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {}); // React logs the caught error
    const reload = vi
      .spyOn(window.location, 'reload')
      .mockImplementation(() => {}); // happy-dom: configurable (jsdom's is not)
    const Bomb = () => {
      throw new Error('kaboom during render');
    };
    render(
      <ErrorBoundary>
        <Bomb />
      </ErrorBoundary>,
    );
    expect(screen.getByText('Something went wrong loading this page')).toBeInTheDocument();
    expect(screen.getByText('kaboom during render')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Reload' }));
    expect(reload).toHaveBeenCalledTimes(1);
  });
});
