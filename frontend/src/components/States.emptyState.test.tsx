// EmptyState is the list layer's shared "there is nothing here" surface. Hosts
// and Hunts already gave it an explainer and a way forward; Investigations said
// "No investigations yet." and stopped, which tells a new operator nothing about
// how a first investigation ever comes to exist (dogfood B1, 2026-08-11). The
// component now carries that shape itself so no screen has to reinvent it.
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { EmptyState } from './States';

describe('EmptyState', () => {
  it('renders a bare message, as the older callers pass it', () => {
    render(<EmptyState>No hosts match the current filters.</EmptyState>);
    expect(screen.getByText('No hosts match the current filters.')).toBeInTheDocument();
  });

  it('renders a headline, an explainer and a primary action together', () => {
    render(
      <EmptyState
        title="No investigations yet"
        action={<a href="/alerts">Start from Alerts</a>}
      >
        An investigation starts from a detection.
      </EmptyState>,
    );
    expect(screen.getByText('No investigations yet')).toBeInTheDocument();
    expect(screen.getByText('An investigation starts from a detection.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Start from Alerts' })).toBeInTheDocument();
  });

  it('omits the headline and action rows when a caller gives neither', () => {
    const { container } = render(<EmptyState>Nothing here.</EmptyState>);
    expect(container.querySelectorAll('div').length).toBeLessThanOrEqual(3);
  });
});
