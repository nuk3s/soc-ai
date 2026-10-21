// Settings number fields clipped the value: w-[62px] showed 32000 as "320"
// and 0.02 as "0.0". The field had no accessible name and no min or max, and
// an out-of-range value met its first word only at Apply, in the raw key
// (dogfood 2026-10-19, R5-D1, R5-D23, H1-D23, R5-I7).
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { NUMBER_FIELD_PAD_PX, NumberField, numberFieldChars, parseBounds } from './Controls';

describe('NumberField', () => {
  it('is wide enough for the value and the bounds', () => {
    expect(numberFieldChars(32000, 256, 32000)).toBeGreaterThanOrEqual(5);
    expect(numberFieldChars(0.02, 0, 1)).toBeGreaterThanOrEqual(4);
    expect(numberFieldChars(1440, 15, 1440)).toBeGreaterThanOrEqual(4);
    render(<NumberField value={32000} bounds="256 to 32000" label="Maximum response tokens" />);
    const input = screen.getByRole('spinbutton', { name: 'Maximum response tokens' });
    expect(input.style.width).toBe(`calc(5ch + ${NUMBER_FIELD_PAD_PX}px)`);
    expect(input).toHaveAttribute('min', '256');
    expect(input).toHaveAttribute('max', '32000');
  });

  // Round 2: 0.15 still showed "0.1" and half a 5. The 34 px beside the
  // characters held the two paddings and the borders, 22 px, and left 12 px
  // for a spinner of 15 px. Chromium clipped every value by 3 px. 40 px is the
  // least that fits.
  it('adds room for the padding, the borders and the spinner', () => {
    expect(NUMBER_FIELD_PAD_PX).toBeGreaterThanOrEqual(40);
    render(<NumberField value={0.15} bounds="0.0 to 1.0" label="Quality drop" />);
    const input = screen.getByRole('spinbutton', { name: 'Quality drop' });
    expect(input.style.width).toBe(`calc(4ch + ${NUMBER_FIELD_PAD_PX}px)`);
  });

  it('sizes by the longest of the value, the bounds and the step', () => {
    // The bound text counts as typed: "0.25" is four characters.
    expect(numberFieldChars(0.5, 0, 1, { texts: ['0.25', '1.00'] })).toBe(4);
    // A step of 0.001 needs five characters for a value such as 0.125.
    expect(numberFieldChars(0.5, 0, 1, { step: 0.001 })).toBe(5);
    expect(numberFieldChars(123456, 1, 1_000_000)).toBe(7);
  });

  it('names the label and the range for a value outside it, and stages nothing', () => {
    const onChange = vi.fn();
    render(
      <NumberField value={90} bounds="1 to 365" label="Memory window (days)" onChange={onChange} />,
    );
    const input = screen.getByRole('spinbutton', { name: 'Memory window (days)' });
    fireEvent.change(input, { target: { value: '999' } });
    expect(screen.getByRole('alert')).toHaveTextContent('Memory window (days) must be from 1 to 365.');
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(onChange).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: '60' } });
    expect(screen.queryByRole('alert')).toBeNull();
    expect(onChange).toHaveBeenCalledWith(60);
  });

  it('keeps the bound text of a float range', () => {
    const onChange = vi.fn();
    render(<NumberField value={0.15} bounds="0.0 to 1.0" label="Quality drop" onChange={onChange} />);
    fireEvent.change(screen.getByRole('spinbutton'), { target: { value: '1.5' } });
    expect(screen.getByRole('alert')).toHaveTextContent('Quality drop must be from 0.0 to 1.0.');
  });

  it('parses an open bound', () => {
    expect(parseBounds('∞ to 100')).toEqual({ min: undefined, max: 100 });
    expect(parseBounds('1 to 365')).toEqual({ min: 1, max: 365 });
    expect(parseBounds(undefined)).toEqual({});
  });
});
