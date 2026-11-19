// Dogfood 2026-11-17, AB5: a lead observation chip and a finding chip printed
// "t_query_events_oql zeek.http destination.ip:192.0.2.5 groupby http.uri".
// The chip shows plain words from the one label map, and its tooltip keeps
// the tool name.
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { DocumentChip } from './DocumentDrawer';

describe('DocumentChip: a tool citation reads in words', () => {
  it('shows the words and keeps the tool name in the tooltip', () => {
    const cite = 't_query_events_oql zeek.http destination.ip:192.0.2.5 groupby http.uri';
    render(<DocumentChip id={cite} />);
    const chip = screen.getByTestId('citation-words');
    expect(chip.textContent).toBe('Event search: zeek.http destination.ip:192.0.2.5 groupby http.uri');
    expect(chip.getAttribute('title')).toBe(`The record cites a tool result: ${cite}`);
    expect(chip.tagName).toBe('SPAN');
  });

  it('keeps a document id as a button that opens the document', () => {
    // NEGATIVE CONTROL: a document id stays the proof that opens its document.
    render(<DocumentChip id="2DewhKEB6RQ6BUvoRR_O" />);
    expect(screen.queryByTestId('citation-words')).toBeNull();
    expect(screen.getByRole('button', { name: '2DewhKEB6RQ6BUvoRR_O' })).toBeTruthy();
  });
});
