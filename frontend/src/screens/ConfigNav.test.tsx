// DESIGN Q5 — below 1024px the sidebar ConfigNav is `hidden ... lg:block` with no
// replacement, so a narrow-viewport operator had no way to jump between config
// sections. ConfigNavSelect is the sub-lg substitute: a sticky "Jump to section"
// <select> mirroring the same grouped section list, expanding + snapping to the
// chosen section via the same scroll/expand mechanism the sidebar uses.
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ConfigNavSelect, type ConfigNavGroup } from './ConfigNav';

const GROUPS: ConfigNavGroup[] = [
  {
    label: 'Models & Reasoning',
    children: [
      { id: 'agent', label: 'Analyst model' },
      { id: 'agent-tools', label: 'Agent tools' },
    ],
  },
  {
    label: 'System',
    children: [
      { id: 'users', label: 'Users' },
      { id: 'danger-zone', label: 'Danger Zone' },
    ],
  },
];

describe('ConfigNavSelect (sub-lg jump nav)', () => {
  it('mirrors the grouped section list as optgroups + one option per sub-section', () => {
    render(<ConfigNavSelect groups={GROUPS} activeId="" />);
    const select = screen.getByRole('combobox') as HTMLSelectElement;
    const optgroups = Array.from(select.querySelectorAll('optgroup')).map((o) => o.label);
    expect(optgroups).toEqual(['Models & Reasoning', 'System']);
    // Every sub-section is a selectable option.
    expect(screen.getByRole('option', { name: 'Analyst model' })).toBeTruthy();
    expect(screen.getByRole('option', { name: 'Agent tools' })).toBeTruthy();
    expect(screen.getByRole('option', { name: 'Users' })).toBeTruthy();
    expect(screen.getByRole('option', { name: 'Danger Zone' })).toBeTruthy();
  });

  it('expands + navigates to the chosen section on change (shared scroll/expand path)', () => {
    const onNavigate = vi.fn();
    render(<ConfigNavSelect groups={GROUPS} activeId="" onNavigate={onNavigate} />);
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'users' } });
    expect(onNavigate).toHaveBeenCalledWith('users');
  });

  it('does not navigate when the disabled placeholder is (re)selected', () => {
    const onNavigate = vi.fn();
    render(<ConfigNavSelect groups={GROUPS} activeId="" onNavigate={onNavigate} />);
    fireEvent.change(screen.getByRole('combobox'), { target: { value: '' } });
    expect(onNavigate).not.toHaveBeenCalled();
  });

  it('reflects the active section, falling back to the placeholder when unknown', () => {
    const { rerender } = render(<ConfigNavSelect groups={GROUPS} activeId="danger-zone" />);
    expect((screen.getByRole('combobox') as HTMLSelectElement).value).toBe('danger-zone');
    rerender(<ConfigNavSelect groups={GROUPS} activeId="not-a-section" />);
    expect((screen.getByRole('combobox') as HTMLSelectElement).value).toBe('');
  });

  // Master-detail: choosing a section SELECTS it (the page renders only that
  // one) — goToSection no longer scrolls at all, so the old sticky-bar
  // scroll-margin regression is structurally impossible. Pin that: no scroll
  // side effects on the target, selection is the only outcome.
  it('selects without scrolling — no scroll side effects on the target', () => {
    const target = document.createElement('div');
    target.id = 'users';
    target.scrollIntoView = vi.fn();
    document.body.appendChild(target);

    const onNavigate = vi.fn();
    render(<ConfigNavSelect groups={GROUPS} activeId="" onNavigate={onNavigate} />);
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'users' } });

    expect(onNavigate).toHaveBeenCalledWith('users');
    expect(target.scrollIntoView).not.toHaveBeenCalled();
    expect(target.style.scrollMarginTop).toBe('');

    document.body.removeChild(target);
  });
});
