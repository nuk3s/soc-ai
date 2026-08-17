// The one toolbar the four list screens share. These tests pin the contract the
// screens rely on: preset chips and saved-view chips read alike, the search box
// is opt-in, and a selection takes over the facet row rather than pushing the
// table down.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ListToolbar } from './ListToolbar';

describe('ListToolbar', () => {
  it('renders the screen\'s own facet controls as children', () => {
    render(
      <ListToolbar>
        <button>Verdict</button>
      </ListToolbar>,
    );
    expect(screen.getByText('Verdict')).toBeInTheDocument();
  });

  it('has no search box unless the screen opts in', () => {
    render(<ListToolbar />);
    expect(screen.queryByRole('searchbox')).toBeNull();
  });

  it('renders an opt-in search box and reports every keystroke', () => {
    const onChange = vi.fn();
    render(<ListToolbar search={{ value: '', onChange, placeholder: 'Search runs…' }} />);
    const box = screen.getByPlaceholderText('Search runs…');
    fireEvent.change(box, { target: { value: 'ssh' } });
    expect(onChange).toHaveBeenCalledWith('ssh');
  });

  it('renders preset chips with their counts and reports a click', () => {
    const onPreset = vi.fn();
    render(
      <ListToolbar
        presets={[
          { id: 'mine', label: 'Mine', count: 3, active: false },
          { id: 'all', label: 'All', count: 9, active: true },
        ]}
        onPreset={onPreset}
      />,
    );
    expect(screen.getByText('Mine')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    fireEvent.click(screen.getByText('Mine'));
    expect(onPreset).toHaveBeenCalledWith('mine');
  });

  it('marks the active preset chip as pressed', () => {
    render(
      <ListToolbar
        presets={[
          { id: 'mine', label: 'Mine', active: false },
          { id: 'all', label: 'All', active: true },
        ]}
        onPreset={vi.fn()}
      />,
    );
    expect(screen.getByRole('button', { name: /All/ })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('button', { name: /Mine/ })).toHaveAttribute('aria-pressed', 'false');
  });

  it('applies a saved view when its chip is clicked', () => {
    const onApplyView = vi.fn();
    const view = { id: 7, name: 'Beacons, last week' };
    render(<ListToolbar views={[view]} onApplyView={onApplyView} />);
    fireEvent.click(screen.getByText('Beacons, last week'));
    expect(onApplyView).toHaveBeenCalledWith(view);
  });

  it('captures the current filters under a typed name', async () => {
    const onSaveView = vi.fn();
    render(<ListToolbar onSaveView={onSaveView} />);
    fireEvent.click(screen.getByRole('button', { name: /save view/i }));
    const name = screen.getByPlaceholderText(/name this view/i);
    fireEvent.change(name, { target: { value: 'My critical hosts' } });
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    expect(onSaveView).toHaveBeenCalledWith('My critical hosts');
    // The composer closes once the name is taken.
    expect(screen.queryByPlaceholderText(/name this view/i)).toBeNull();
  });

  it('keeps the composer and the typed name when the save is refused', async () => {
    // Closing first threw the name away on every refusal, so a real
    // `too_many_views` produced no chip, no name and no message.
    const onSaveView = vi.fn().mockRejectedValue(new Error('400 too_many_views'));
    const { rerender } = render(<ListToolbar onSaveView={onSaveView} />);
    fireEvent.click(screen.getByRole('button', { name: /save view/i }));
    fireEvent.change(screen.getByPlaceholderText(/name this view/i), {
      target: { value: 'Beacons' },
    });
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    await waitFor(() => expect(onSaveView).toHaveBeenCalledWith('Beacons'));

    // Still open, still holding what was typed.
    expect(screen.getByPlaceholderText(/name this view/i)).toHaveValue('Beacons');

    rerender(<ListToolbar onSaveView={onSaveView} viewError="You have reached the saved-view limit." />);
    expect(screen.getByRole('alert')).toHaveTextContent(/limit/i);
  });

  it('closes the composer once an async save actually lands', async () => {
    const onSaveView = vi.fn().mockResolvedValue(undefined);
    render(<ListToolbar onSaveView={onSaveView} />);
    fireEvent.click(screen.getByRole('button', { name: /save view/i }));
    fireEvent.change(screen.getByPlaceholderText(/name this view/i), {
      target: { value: 'Beacons' },
    });
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    await waitFor(() => expect(screen.queryByPlaceholderText(/name this view/i)).toBeNull());
  });

  it('refuses to save a blank name', () => {
    const onSaveView = vi.fn();
    render(<ListToolbar onSaveView={onSaveView} />);
    fireEvent.click(screen.getByRole('button', { name: /save view/i }));
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    expect(onSaveView).not.toHaveBeenCalled();
  });

  it('deletes a saved view from its chip, once the delete is confirmed', () => {
    // The × used to delete on the first click: no confirm, no undo, and the
    // server row gone. It sits inside the chip, a few pixels from the chip's
    // own click target. Same arm-then-confirm as every other destructive
    // action in the app (a runbook row, a hunt, an investigation).
    const onDeleteView = vi.fn();
    const view = { id: 7, name: 'Beacons' };
    render(<ListToolbar views={[view]} onApplyView={vi.fn()} onDeleteView={onDeleteView} />);

    fireEvent.click(screen.getByRole('button', { name: /delete the saved view "Beacons"/i }));
    expect(onDeleteView).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: /confirm delete of the saved view "Beacons"/i }));
    expect(onDeleteView).toHaveBeenCalledWith(view);
  });

  it('lets an armed delete be called off, chip intact', () => {
    const onDeleteView = vi.fn();
    const view = { id: 7, name: 'Beacons' };
    render(<ListToolbar views={[view]} onApplyView={vi.fn()} onDeleteView={onDeleteView} />);

    fireEvent.click(screen.getByRole('button', { name: /delete the saved view "Beacons"/i }));
    fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }));
    expect(onDeleteView).not.toHaveBeenCalled();
    // Back to a normal, appliable chip.
    expect(screen.getByRole('button', { name: 'Beacons' })).toBeInTheDocument();
  });

  it('arms one view at a time', () => {
    const views = [
      { id: 7, name: 'Beacons' },
      { id: 8, name: 'Scanners' },
    ];
    render(<ListToolbar views={views} onApplyView={vi.fn()} onDeleteView={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: /delete the saved view "Beacons"/i }));
    fireEvent.click(screen.getByRole('button', { name: /delete the saved view "Scanners"/i }));
    expect(
      screen.queryByRole('button', { name: /confirm delete of the saved view "Beacons"/i }),
    ).toBeNull();
    expect(
      screen.getByRole('button', { name: /confirm delete of the saved view "Scanners"/i }),
    ).toBeInTheDocument();
  });

  it('shows no chip row at all when a screen has neither presets nor views', () => {
    render(<ListToolbar />);
    expect(screen.queryByTestId('list-toolbar-views')).toBeNull();
  });

  it('shows the selection count and the screen\'s bulk actions when rows are picked', () => {
    render(
      <ListToolbar
        selection={{ count: 3, onClear: vi.fn(), actions: <button>Re-investigate</button> }}
      >
        <button>Verdict</button>
      </ListToolbar>,
    );
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText(/selected/i)).toBeInTheDocument();
    expect(screen.getByText('Re-investigate')).toBeInTheDocument();
  });

  it('keeps the facet row and the search box while a selection is active', () => {
    // The controls that produced the list must survive the selection. An
    // earlier cut swapped the facet row out for the strip, which on Hunts
    // removed the screen's ONLY filter, blanked a typed search term that was
    // still applied server-side, and left "Clear" — which discards the
    // selection — as the only way back to the controls.
    const onChange = vi.fn();
    const { rerender } = render(
      <ListToolbar search={{ value: 'ssh', onChange, placeholder: 'Search runs…' }}>
        <button>Verdict</button>
      </ListToolbar>,
    );
    expect(screen.getByText('Verdict')).toBeInTheDocument();
    rerender(
      <ListToolbar
        search={{ value: 'ssh', onChange, placeholder: 'Search runs…' }}
        selection={{ count: 1, onClear: vi.fn() }}
      >
        <button>Verdict</button>
      </ListToolbar>,
    );
    expect(screen.getByText('Verdict')).toBeInTheDocument();
    // The term is still applied server-side, so it must still be on screen.
    expect(screen.getByPlaceholderText('Search runs…')).toHaveValue('ssh');
    // …and still editable, without discarding the selection first.
    fireEvent.change(screen.getByPlaceholderText('Search runs…'), { target: { value: 'ssh key' } });
    expect(onChange).toHaveBeenCalledWith('ssh key');
    expect(screen.getByText(/selected/i)).toBeInTheDocument();
  });

  it('renders the selection strip as its own row, not inside the facet row', () => {
    render(
      <ListToolbar selection={{ count: 2, onClear: vi.fn() }}>
        <button>Verdict</button>
      </ListToolbar>,
    );
    const strip = screen.getByTestId('list-toolbar-selection');
    expect(strip).toBeInTheDocument();
    expect(strip).not.toContainElement(screen.getByText('Verdict'));
  });

  it('says how much of the selection this page cannot show', () => {
    // Silent persistence is the trap: the count says 9, the operator sees 3,
    // and a bulk action submits six ids nothing on screen renders.
    render(<ListToolbar selection={{ count: 9, offPageCount: 6, onClear: vi.fn() }} />);
    expect(screen.getByText(/6 not on this page/i)).toBeInTheDocument();
  });

  it('says nothing about off-page rows when every selected row is visible', () => {
    render(<ListToolbar selection={{ count: 3, offPageCount: 0, onClear: vi.fn() }} />);
    expect(screen.queryByText(/not on this page/i)).toBeNull();
  });

  it('drops just the off-page ids from the disclosure marker', () => {
    const onClearOffPage = vi.fn();
    const onClear = vi.fn();
    render(
      <ListToolbar selection={{ count: 9, offPageCount: 6, onClear, onClearOffPage }} />,
    );
    fireEvent.click(screen.getByText(/6 not on this page/i));
    expect(onClearOffPage).toHaveBeenCalled();
    expect(onClear).not.toHaveBeenCalled();
  });

  it('lets a screen replace the count line when one number cannot say it', () => {
    render(
      <ListToolbar
        selection={{ count: 4, onClear: vi.fn(), summary: <>2 groups · 2 events</> }}
      />,
    );
    expect(screen.getByText('2 groups · 2 events')).toBeInTheDocument();
    expect(screen.queryByText(/^selected$/)).toBeNull();
  });

  it('clears the selection', () => {
    const onClear = vi.fn();
    render(<ListToolbar selection={{ count: 2, onClear }} />);
    fireEvent.click(screen.getByRole('button', { name: /^clear$/i }));
    expect(onClear).toHaveBeenCalled();
  });

  it('keeps trailing controls in place whether or not rows are selected', () => {
    const { rerender } = render(<ListToolbar trailing={<button>Rebuild now</button>} />);
    expect(screen.getByText('Rebuild now')).toBeInTheDocument();
    rerender(
      <ListToolbar trailing={<button>Rebuild now</button>} selection={{ count: 1, onClear: vi.fn() }} />,
    );
    expect(screen.getByText('Rebuild now')).toBeInTheDocument();
  });

  it('renders a transient note beside the controls', () => {
    render(<ListToolbar note="Deleted 2 investigations" />);
    expect(screen.getByText('Deleted 2 investigations')).toBeInTheDocument();
  });
});
