// Pins ManagedList's large-list affordances — filter, paging, bulk selection —
// and, most importantly, that a call site passing none of them still renders
// exactly what it rendered before (every row, no checkbox, no filter input).
//
// Row count is read off the per-row Active toggle (one switch per rendered row),
// which is the only per-row control that is always present.
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { IdentifierRow } from '../lib/api';
import { ManagedList } from './ManagedList';

function row(overrides: Partial<IdentifierRow> = {}): IdentifierRow {
  return {
    id: 1,
    value: 'alpha-001.example.internal',
    source: 'detected',
    state: 'active',
    evidence: null,
    mutable: true,
    ...overrides,
  };
}

/** `n` detected rows valued `<prefix>-NNN.example.internal`, ids from `startId`. */
function manyRows(n: number, prefix = 'alpha', startId = 1): IdentifierRow[] {
  return Array.from({ length: n }, (_, i) =>
    row({ id: startId + i, value: `${prefix}-${String(i + 1).padStart(3, '0')}.example.internal` }),
  );
}

function baseProps() {
  return {
    title: 'Bare hostnames',
    onAdd: vi.fn(),
    onSetActive: vi.fn(),
    onRemove: vi.fn(),
  };
}

/** The values of the currently rendered rows, in render order. */
function visibleValues(): string[] {
  return screen
    .getAllByRole('switch')
    .map((el) => (el.getAttribute('aria-label') ?? '').replace('Active — ', ''));
}

describe('ManagedList — no optional props (unchanged behaviour)', () => {
  it('renders every row with no filter input and no checkboxes', () => {
    render(<ManagedList {...baseProps()} rows={manyRows(6)} onDismiss={vi.fn()} />);

    expect(visibleValues()).toHaveLength(6);
    expect(screen.queryByPlaceholderText('Filter…')).not.toBeInTheDocument();
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0);
    expect(screen.queryByRole('button', { name: /^Show /})).not.toBeInTheDocument();
    // the existing add input and per-row dismiss survive
    expect(screen.getByPlaceholderText('add value…')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Dismiss' })).toHaveLength(6);
  });

  it('keeps the per-row two-press dismiss confirm', async () => {
    const user = userEvent.setup();
    const onDismiss = vi.fn();
    render(<ManagedList {...baseProps()} rows={manyRows(2)} onDismiss={onDismiss} />);

    await user.click(screen.getAllByRole('button', { name: 'Dismiss' })[1]);
    expect(onDismiss).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(onDismiss).toHaveBeenCalledWith(2);
  });
});

describe('ManagedList — searchable', () => {
  const mixed = [
    ...manyRows(2, 'alpha', 1),
    row({ id: 3, value: 'BETA-001.example.internal' }),
  ];

  it('filters rows case-insensitively on value and shows the count line', async () => {
    const user = userEvent.setup();
    render(<ManagedList {...baseProps()} rows={mixed} searchable />);

    expect(visibleValues()).toHaveLength(3);
    expect(screen.queryByText('3 of 3 shown')).not.toBeInTheDocument();

    await user.type(screen.getByPlaceholderText('Filter…'), 'beta');
    expect(visibleValues()).toEqual(['BETA-001.example.internal']);
    expect(screen.getByText('1 of 3 shown')).toBeInTheDocument();
  });

  it('drops the count line and restores every row when the filter is cleared', async () => {
    const user = userEvent.setup();
    render(<ManagedList {...baseProps()} rows={mixed} searchable />);

    const input = screen.getByPlaceholderText('Filter…');
    await user.type(input, 'alpha');
    expect(visibleValues()).toHaveLength(2);
    await user.clear(input);
    expect(visibleValues()).toHaveLength(3);
    expect(screen.queryByText(/ of 3 shown$/)).not.toBeInTheDocument();
  });

  it('shows an empty state when nothing matches', async () => {
    const user = userEvent.setup();
    render(<ManagedList {...baseProps()} rows={mixed} searchable />);

    await user.type(screen.getByPlaceholderText('Filter…'), 'gamma');
    expect(screen.queryAllByRole('switch')).toHaveLength(0);
    expect(screen.getByText('0 of 3 shown')).toBeInTheDocument();
  });
});

describe('ManagedList — pageSize', () => {
  it('truncates to pageSize and expands to the full list on click', async () => {
    const user = userEvent.setup();
    render(<ManagedList {...baseProps()} rows={manyRows(30)} pageSize={10} />);

    expect(visibleValues()).toHaveLength(10);
    await user.click(screen.getByRole('button', { name: 'Show all 30' }));
    expect(visibleValues()).toHaveLength(30);

    await user.click(screen.getByRole('button', { name: 'Show first 10' }));
    expect(visibleValues()).toHaveLength(10);
  });

  it('renders no expand button when the list already fits', () => {
    render(<ManagedList {...baseProps()} rows={manyRows(8)} pageSize={10} />);

    expect(visibleValues()).toHaveLength(8);
    expect(screen.queryByRole('button', { name: /^Show / })).not.toBeInTheDocument();
  });

  it('pages the FILTERED rows and resets to truncated when the filter changes', async () => {
    const user = userEvent.setup();
    const rows = [...manyRows(30, 'alpha', 1), ...manyRows(12, 'beta', 100)];
    render(<ManagedList {...baseProps()} rows={rows} searchable pageSize={10} />);

    const input = screen.getByPlaceholderText('Filter…');
    await user.type(input, 'beta');
    expect(visibleValues()).toHaveLength(10);
    expect(screen.getByText('12 of 42 shown')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Show all 12' }));
    expect(visibleValues()).toHaveLength(12);

    // typing one more character resets paging back to the truncated state
    await user.type(input, '-0');
    expect(visibleValues()).toHaveLength(10);
    expect(screen.getByRole('button', { name: 'Show all 12' })).toBeInTheDocument();
  });
});

describe('ManagedList — bulk', () => {
  const bulkRows: IdentifierRow[] = [
    row({ id: 1, value: 'alpha-001.example.internal' }),
    row({ id: 2, value: 'alpha-002.example.internal', source: 'manual' }),
    row({ id: 3, value: 'alpha-003.example.internal' }),
    row({ id: null, value: '192.0.2.0/24', source: 'env', mutable: false }),
    row({ id: 9, value: '198.51.100.0/24', source: 'reserved', mutable: false }),
  ];

  function bulkProps() {
    return { onSetActiveMany: vi.fn(), onDismissMany: vi.fn() };
  }

  it('renders a checkbox only for mutable rows with an id', () => {
    render(<ManagedList {...baseProps()} rows={bulkRows} bulk={bulkProps()} />);

    const boxes = screen.getAllByRole('checkbox', { name: /^Select (alpha|19)/ });
    expect(boxes.map((b) => b.getAttribute('aria-label'))).toEqual([
      'Select alpha-001.example.internal',
      'Select alpha-002.example.internal',
      'Select alpha-003.example.internal',
    ]);
  });

  it('shows the header bar only once something is selected', async () => {
    const user = userEvent.setup();
    render(<ManagedList {...baseProps()} rows={bulkRows} bulk={bulkProps()} />);

    expect(screen.queryByText('1 selected')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Enable' })).not.toBeInTheDocument();

    await user.click(screen.getByRole('checkbox', { name: 'Select alpha-002.example.internal' }));
    expect(screen.getByText('1 selected')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Enable' })).toBeInTheDocument();
  });

  it('select-all-shown selects exactly the visible (filtered + paged) mutable rows', async () => {
    const user = userEvent.setup();
    const bulk = bulkProps();
    const rows = [...manyRows(12, 'alpha', 1), row({ id: 99, value: 'beta-001.example.internal' })];
    render(<ManagedList {...baseProps()} rows={rows} searchable pageSize={5} bulk={bulk} />);

    await user.click(screen.getByRole('checkbox', { name: 'Select all shown' }));
    expect(screen.getByText('5 selected')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Enable' }));
    expect(bulk.onSetActiveMany).toHaveBeenCalledWith([1, 2, 3, 4, 5], true);
  });

  it('Enable and Disable pass the selected ids and the right boolean', async () => {
    const user = userEvent.setup();
    const bulk = bulkProps();
    render(<ManagedList {...baseProps()} rows={bulkRows} bulk={bulk} />);

    await user.click(screen.getByRole('checkbox', { name: 'Select alpha-002.example.internal' }));
    await user.click(screen.getByRole('checkbox', { name: 'Select alpha-003.example.internal' }));
    await user.click(screen.getByRole('button', { name: 'Disable' }));
    expect(bulk.onSetActiveMany).toHaveBeenCalledWith([2, 3], false);

    await user.click(screen.getByRole('checkbox', { name: 'Select alpha-001.example.internal' }));
    await user.click(screen.getByRole('button', { name: 'Enable' }));
    expect(bulk.onSetActiveMany).toHaveBeenLastCalledWith([1], true);
  });

  it('clears the selection after a bulk action fires', async () => {
    const user = userEvent.setup();
    const bulk = bulkProps();
    render(<ManagedList {...baseProps()} rows={bulkRows} bulk={bulk} />);

    await user.click(screen.getByRole('checkbox', { name: 'Select alpha-001.example.internal' }));
    await user.click(screen.getByRole('button', { name: 'Enable' }));

    expect(screen.queryByText('1 selected')).not.toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Select alpha-001.example.internal' })).not.toBeChecked();
  });

  it('bulk Dismiss needs the confirm press, and Cancel backs out', async () => {
    const user = userEvent.setup();
    const bulk = bulkProps();
    render(<ManagedList {...baseProps()} rows={bulkRows} bulk={bulk} />);

    await user.click(screen.getByRole('checkbox', { name: 'Select alpha-001.example.internal' }));
    await user.click(screen.getByRole('checkbox', { name: 'Select alpha-003.example.internal' }));

    await user.click(screen.getByRole('button', { name: 'Dismiss (2)' }));
    expect(bulk.onDismissMany).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(bulk.onDismissMany).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Dismiss (2)' }));
    await user.click(screen.getByRole('button', { name: 'Confirm dismiss (2)' }));
    expect(bulk.onDismissMany).toHaveBeenCalledWith([1, 3]);
    expect(screen.queryByText('2 selected')).not.toBeInTheDocument();
  });

  it('omits the bulk Dismiss button when onDismissMany is not provided', async () => {
    const user = userEvent.setup();
    render(
      <ManagedList {...baseProps()} rows={bulkRows} bulk={{ onSetActiveMany: vi.fn() }} />,
    );

    await user.click(screen.getByRole('checkbox', { name: 'Select alpha-001.example.internal' }));
    expect(screen.getByRole('button', { name: 'Enable' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Dismiss \(/ })).not.toBeInTheDocument();
  });

  it('drops selected ids that vanish from rows on a refetch', async () => {
    const user = userEvent.setup();
    const bulk = bulkProps();
    const props = baseProps();
    const { rerender } = render(<ManagedList {...props} rows={bulkRows} bulk={bulk} />);

    for (const v of ['alpha-001', 'alpha-002', 'alpha-003']) {
      await user.click(screen.getByRole('checkbox', { name: `Select ${v}.example.internal` }));
    }
    expect(screen.getByText('3 selected')).toBeInTheDocument();

    // id 2 was dismissed elsewhere and is gone from the refetched list
    rerender(<ManagedList {...props} rows={bulkRows.filter((r) => r.id !== 2)} bulk={bulk} />);
    expect(screen.getByText('2 selected')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Enable' }));
    expect(bulk.onSetActiveMany).toHaveBeenCalledWith([1, 3], true);
  });
});
