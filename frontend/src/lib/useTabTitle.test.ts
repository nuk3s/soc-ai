// R3-D15: hunt and lead tabs all read "soc·ai: SOC alert triage".
import { renderHook } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { tabTitle, useTabTitle } from './useTabTitle';

describe('useTabTitle', () => {
  it('names the page, and restores the title on unmount', () => {
    document.title = 'soc·ai: SOC alert triage';
    const view = renderHook(({ name }) => useTabTitle(name), { initialProps: { name: 'Lead 5' } });
    expect(document.title).toBe('Lead 5 · soc·ai');
    view.rerender({ name: 'Lead 6' });
    expect(document.title).toBe('Lead 6 · soc·ai');
    view.unmount();
    expect(document.title).toBe('soc·ai: SOC alert triage');
  });

  it('leaves the title alone while the name is unknown', () => {
    document.title = 'before';
    renderHook(() => useTabTitle(null));
    expect(document.title).toBe('before');
    expect(tabTitle('  ')).toBe('');
  });
});
