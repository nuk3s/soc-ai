// The custom window chip and the custom window picker (dogfood 2026-10-19,
// R2-D17, R2-I7, STE item 23).
//
// The chip read "Aug 25 00:00:00.000Z → Oct 19 12:00:00.000Z": an arrow, the
// milliseconds and a bare "Z" for the zone. It now reads "Aug 25 00:00 UTC to
// Oct 19 12:00 UTC", in the zone the picker means, which is the browser zone.
// The picker opened empty while a custom window was active, so the analyst
// typed the window again to move one edge. It now opens on the active window.
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { customBoundText, pickerValue, TimeRangeFilter } from './TimeRangeFilter';

/** The two datetime-local inputs of the open picker: From, then To. */
function pickerInputs(): [HTMLInputElement, HTMLInputElement] {
  const inputs = Array.from(
    document.querySelectorAll<HTMLInputElement>('input[type="datetime-local"]'),
  );
  expect(inputs).toHaveLength(2);
  return [inputs[0], inputs[1]];
}

/** A wall time in the browser zone, in the datetime-local form. */
function localValue(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    `T${pad(d.getHours())}:${pad(d.getMinutes())}`
  );
}

describe('the custom window chip', () => {
  it('states a bound with no milliseconds and a named zone', () => {
    expect(customBoundText('2026-08-25T00:00:00.000Z', { timeZone: 'UTC' })).toBe(
      'Aug 25 00:00 UTC',
    );
    expect(customBoundText('2026-10-19T12:00:00.000Z', { timeZone: 'UTC' })).toBe(
      'Oct 19 12:00 UTC',
    );
  });

  it('reads a bound with no offset as a wall time in the browser zone', () => {
    // The picker writes "2026-08-25T00:00", a wall time in the browser zone.
    // The chip states that wall time and names the zone.
    const text = customBoundText('2026-08-25T00:00');
    expect(text).toMatch(/^Aug 25 00:00 \S+$/);
  });

  it('keeps an unreadable bound as it came', () => {
    expect(customBoundText('not-a-time')).toBe('not-a-time');
  });

  it('draws "from to to" with no arrow and no milliseconds', () => {
    render(
      <TimeRangeFilter
        value="custom"
        custom={{ from: '2026-08-25T00:00:00.000Z', to: '2026-10-19T12:00:00.000Z' }}
        onChange={() => {}}
      />,
    );
    const chip = screen.getByLabelText('Custom date range');
    const text = chip.textContent ?? '';
    expect(text).not.toContain('→');
    expect(text).not.toContain('.000');
    expect(text).not.toMatch(/\dZ/);
    expect(text).toMatch(/^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2} \S+ to [A-Z][a-z]{2} \d{1,2} \d{2}:\d{2} \S+$/);
    expect(text).toBe(
      `${customBoundText('2026-08-25T00:00:00.000Z')} to ${customBoundText('2026-10-19T12:00:00.000Z')}`,
    );
    // The title gives the year, which the chip leaves out.
    expect(chip.getAttribute('title')).toMatch(
      /^The window starts 2026-\d{2}-\d{2} \d{2}:\d{2} \S+ and ends 2026-10-\d{2} \d{2}:\d{2} \S+\.$/,
    );
  });
});

describe('the custom window picker', () => {
  it('opens on the active custom window', () => {
    render(
      <TimeRangeFilter
        value="custom"
        custom={{ from: '2026-08-25T00:00', to: '2026-10-19T12:00' }}
        onChange={() => {}}
      />,
    );
    fireEvent.click(screen.getByLabelText('Custom date range'));
    const [from, to] = pickerInputs();
    expect(from.value).toBe('2026-08-25T00:00');
    expect(to.value).toBe('2026-10-19T12:00');
  });

  it('opens on a window a link gave as UTC, in the browser zone', () => {
    // A link wrote the bounds as ISO with a "Z". A datetime-local input
    // refuses that form and showed an empty field.
    const fromIso = '2026-08-25T00:00:00.000Z';
    const toIso = '2026-10-19T12:00:00.000Z';
    render(<TimeRangeFilter value="custom" custom={{ from: fromIso, to: toIso }} onChange={() => {}} />);
    fireEvent.click(screen.getByLabelText('Custom date range'));
    const [from, to] = pickerInputs();
    expect(from.value).toBe(localValue(Date.parse(fromIso)));
    expect(to.value).toBe(localValue(Date.parse(toIso)));
  });

  it('opens on a custom window that arrived after the first render', () => {
    // A saved view or a link sets the window after the filter mounted.
    const { rerender } = render(<TimeRangeFilter value="24h" custom={null} onChange={() => {}} />);
    rerender(
      <TimeRangeFilter
        value="custom"
        custom={{ from: '2026-09-01T08:30', to: '2026-09-02T17:45' }}
        onChange={() => {}}
      />,
    );
    fireEvent.click(screen.getByLabelText('Custom date range'));
    const [from, to] = pickerInputs();
    expect(from.value).toBe('2026-09-01T08:30');
    expect(to.value).toBe('2026-09-02T17:45');
  });

  it('opens on the span of the active preset, ending now', () => {
    render(<TimeRangeFilter value="24h" custom={null} onChange={() => {}} />);
    const before = Date.now();
    fireEvent.click(screen.getByLabelText('Custom date range'));
    const [from, to] = pickerInputs();
    // The minute can turn between the click and the check. Accept either.
    expect([localValue(before - 24 * 3_600_000), localValue(Date.now() - 24 * 3_600_000)]).toContain(
      from.value,
    );
    expect([localValue(before), localValue(Date.now())]).toContain(to.value);
  });

  it('sends the edited window in the datetime-local form', () => {
    const onChange = vi.fn();
    render(
      <TimeRangeFilter
        value="custom"
        custom={{ from: '2026-08-25T00:00', to: '2026-10-19T12:00' }}
        onChange={onChange}
      />,
    );
    fireEvent.click(screen.getByLabelText('Custom date range'));
    const [, to] = pickerInputs();
    fireEvent.change(to, { target: { value: '2026-10-18T06:00' } });
    fireEvent.click(screen.getByText('Apply'));
    expect(onChange).toHaveBeenCalledWith('custom', {
      from: '2026-08-25T00:00',
      to: '2026-10-18T06:00',
    });
  });

  it('NEGATIVE CONTROL: leaves the fields alone on a window with no lower edge', () => {
    render(<TimeRangeFilter value="all" custom={null} presets={['24h', 'all']} onChange={() => {}} />);
    fireEvent.click(screen.getByLabelText('Custom date range'));
    const [from, to] = pickerInputs();
    expect(from.value).toBe('');
    expect(to.value).toBe('');
  });
});

describe('pickerValue', () => {
  it('keeps a datetime-local value and drops seconds', () => {
    expect(pickerValue('2026-08-25T00:00')).toBe('2026-08-25T00:00');
    expect(pickerValue('2026-08-25T00:00:30')).toBe('2026-08-25T00:00');
  });

  it('reads an unreadable value as empty', () => {
    expect(pickerValue('garbage')).toBe('');
    expect(pickerValue('')).toBe('');
  });
});
