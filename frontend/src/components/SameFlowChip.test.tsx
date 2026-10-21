// Dogfood 2026-10-19, R2-I9 and R2-D9. An SQL injection alert and a Geoserver
// alert shared one flow and showed as two unrelated rows. The NTLMv1 group (a
// false positive) and the WMIExec group (a true positive) fired 2.6 s apart
// between the same two hosts, and neither row named the other.
import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { AlertSibling } from '../lib/types';
import { SameFlowChip, oppositeVerdictSentence } from './SameFlowChip';

const WMI = 'ET INFO Suspected Impacket WMIExec Activity';
const SCAN = 'ET SCAN Suspicious inbound to MSSQL port 1433';

const sib = (o: Partial<AlertSibling> = {}): AlertSibling => ({
  name: WMI,
  kind: 'suricata',
  verdict: 'true_positive',
  conf: 0.72,
  invId: 'inv-wmi',
  signals: ['hosts'],
  ...o,
});

function renderChip(over: Partial<Parameters<typeof SameFlowChip>[0]> = {}) {
  const onShow = vi.fn();
  const onOpen = vi.fn();
  render(
    <SameFlowChip
      verdict="false_positive"
      siblings={[sib()]}
      count={1}
      onShow={onShow}
      onOpen={onOpen}
      {...over}
    />,
  );
  return { onShow, onOpen, chip: screen.getByTestId('same-flow-chip') };
}

describe('the same-flow chip', () => {
  it('names the count', () => {
    const { chip } = renderChip({
      verdict: 'untriaged',
      siblings: [sib({ verdict: 'untriaged' }), sib({ name: SCAN, verdict: 'untriaged' })],
      count: 2,
    });
    expect(chip.textContent).toContain('Same flow');
    expect(chip.textContent).toContain('2');
    expect(chip.getAttribute('aria-label')).toBe('2 other detections share this flow. Show them.');
    expect(chip.getAttribute('data-tone')).toBe('neutral');
  });

  it('uses the warning tone and says so when a true positive shares the flow of a false positive', () => {
    const { chip } = renderChip();
    expect(chip.getAttribute('data-tone')).toBe('warning');
    expect(chip.textContent).toContain('A true positive shares this flow.');
    expect(chip.getAttribute('aria-label')).toBe(
      'A true positive shares this flow. 1 other detection shares this flow. Show them.',
    );
  });

  it('says so the other way round on the true positive row', () => {
    const { chip } = renderChip({ verdict: 'true_positive', siblings: [sib({ verdict: 'false_positive' })] });
    expect(chip.getAttribute('data-tone')).toBe('warning');
    expect(chip.textContent).toContain('A false positive shares this flow.');
  });

  it('NEGATIVE CONTROL: two verdicts that agree keep the neutral tone', () => {
    const { chip } = renderChip({ verdict: 'true_positive' });
    expect(chip.getAttribute('data-tone')).toBe('neutral');
    expect(chip.textContent).not.toContain('shares this flow.');
  });

  it('NEGATIVE CONTROL: an untriaged sibling of a false positive is not an opposite verdict', () => {
    expect(oppositeVerdictSentence('false_positive', [sib({ verdict: 'untriaged' })])).toBeNull();
    expect(oppositeVerdictSentence('needs_more_info', [sib()])).toBeNull();
    expect(oppositeVerdictSentence(null, [sib()])).toBeNull();
  });

  it('opens a popover that lists each sibling with its verdict and the signal', () => {
    const { chip } = renderChip({
      siblings: [sib(), sib({ name: SCAN, verdict: 'untriaged', invId: null, signals: ['flow', 'hosts'] })],
      count: 2,
    });
    fireEvent.click(chip);
    const pop = screen.getByTestId('same-flow-popover');
    const rows = within(pop).getAllByTestId('same-flow-sibling');
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain(WMI);
    expect(rows[0].textContent).toContain('True positive');
    expect(rows[0].textContent).toContain('Same two hosts within 5 minutes');
    expect(rows[1].textContent).toContain(SCAN);
    expect(rows[1].textContent).toContain('Untriaged');
    expect(rows[1].textContent).toContain('Same community ID within 1 hour');
  });

  it('links each sibling to its row and to its report', () => {
    const { chip, onShow, onOpen } = renderChip();
    fireEvent.click(chip);
    const pop = screen.getByTestId('same-flow-popover');
    fireEvent.click(within(pop).getByRole('button', { name: `Show ${WMI}` }));
    expect(onShow).toHaveBeenCalledWith(expect.objectContaining({ name: WMI, kind: 'suricata' }));
    fireEvent.click(chip);
    fireEvent.click(within(screen.getByTestId('same-flow-popover')).getByRole('button', { name: `Open the report of ${WMI}` }));
    expect(onOpen).toHaveBeenCalledWith('inv-wmi');
  });

  it('NEGATIVE CONTROL: an untriaged sibling has no report to open', () => {
    const { chip } = renderChip({ siblings: [sib({ verdict: 'untriaged', invId: null })] });
    fireEvent.click(chip);
    const pop = screen.getByTestId('same-flow-popover');
    expect(within(pop).queryByRole('button', { name: /Open the report/ })).toBeNull();
    expect(within(pop).getByRole('button', { name: `Show ${WMI}` })).toBeTruthy();
  });

  it('names the siblings the list leaves out', () => {
    const { chip } = renderChip({ count: 23 });
    fireEvent.click(chip);
    expect(screen.getByTestId('same-flow-popover').textContent).toContain('22 more detections share this flow.');
  });

  it('closes on Escape, and a click on the chip does not reach the row', () => {
    const rowClick = vi.fn();
    render(
      <div onClick={rowClick}>
        <SameFlowChip verdict="false_positive" siblings={[sib()]} count={1} onShow={vi.fn()} onOpen={vi.fn()} />
      </div>,
    );
    fireEvent.click(screen.getByTestId('same-flow-chip'));
    expect(rowClick).not.toHaveBeenCalled();
    expect(screen.getByTestId('same-flow-popover')).toBeTruthy();
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(screen.queryByTestId('same-flow-popover')).toBeNull();
  });

  it('says the count is a floor and the list can be partial when the read was cut (V3-N1)', () => {
    const { chip } = renderChip({ verdict: 'untriaged', siblings: [sib({ verdict: 'untriaged' })], count: 1, partial: true });
    expect(chip.textContent).toContain('1+');
    expect(chip.getAttribute('aria-label')).toBe('At least 1 other detection shares this flow. Show them.');
    fireEvent.click(chip);
    const pop = screen.getByTestId('same-flow-popover');
    expect(pop.textContent).toContain('At least 1 other detection shares this flow.');
    expect(within(pop).getByTestId('same-flow-note').textContent).toContain('The list can be partial.');
  });

  it('NEGATIVE CONTROL: a whole read states the exact count and no partial list', () => {
    const { chip } = renderChip({ verdict: 'untriaged', siblings: [sib({ verdict: 'untriaged' })], count: 1, partial: false });
    expect(chip.textContent).not.toContain('+');
    expect(chip.getAttribute('aria-label')).toBe('1 other detection shares this flow. Show them.');
    fireEvent.click(chip);
    expect(screen.getByTestId('same-flow-popover').textContent).not.toContain('partial');
  });

  it('caps the height of the popover, scrolls the list, and keeps the note in view (V3-N7)', () => {
    // At 1280x800 the popover of 16 siblings was 1149 px tall and the note
    // sat below the screen.
    const many = Array.from({ length: 16 }, (_, i) =>
      sib({ name: `ET TEST rule ${i}`, verdict: 'untriaged', invId: null }),
    );
    const { chip } = renderChip({ verdict: 'untriaged', siblings: many, count: 16 });
    fireEvent.click(chip);
    const pop = screen.getByTestId('same-flow-popover');
    const list = within(pop).getByTestId('same-flow-list');
    const note = within(pop).getByTestId('same-flow-note');
    expect(pop.className).toMatch(/(^| )max-h-\[/);
    expect(pop.className).toContain('flex-col');
    expect(list.className).toContain('overflow-y-auto');
    expect(list.className).toContain('min-h-0');
    // The note is outside the part that scrolls.
    expect(list.contains(note)).toBe(false);
    expect(note.className).toContain('flex-none');
    expect(within(list).getAllByTestId('same-flow-sibling')).toHaveLength(16);
  });

  it('states both signals as two alerts close in time', () => {
    const { chip } = renderChip();
    fireEvent.click(chip);
    const note = screen.getByTestId('same-flow-note').textContent;
    expect(note).toContain(
      'Two detections share a flow when an alert of each has the same community ID within 1 hour of the other.',
    );
    expect(note).toContain(
      'They also share a flow when an alert of each runs between the same two hosts within 5 minutes of the other.',
    );
  });

  it('shows a sibling with no verdict as a pipeline error', () => {
    const { chip } = renderChip({ siblings: [sib({ verdict: null })] });
    fireEvent.click(chip);
    expect(screen.getByTestId('same-flow-popover').textContent).toContain('Pipeline error');
  });
});
