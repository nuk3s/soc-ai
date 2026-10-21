// Dogfood 2026-10-19, R2-D9. The NTLMv1 report (a false positive) and the
// WMIExec report (a true positive) covered one attack step 2.6 s apart
// between the same two hosts. Neither report named the other.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AlertSibling } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../lib/api')>();
  return { ...orig, getInvestigationSiblings: vi.fn() };
});

import { getInvestigationSiblings } from '../lib/api';
import { SameFlowPanel, siblingRowHref } from './SameFlowPanel';

const NTLM = 'ET INFO NTLMv1 Session Setup Response - Challenge';
const GEO = 'ET WEB_SPECIFIC_APPS Geoserver Unsafe jxpath Evaluation RCE Attempt';

const sib = (o: Partial<AlertSibling> = {}): AlertSibling => ({
  name: NTLM,
  kind: 'suricata',
  verdict: 'false_positive',
  conf: 0.8,
  invId: 'inv-ntlm',
  signals: ['hosts'],
  ...o,
});

function renderPanel(verdict = 'true_positive') {
  return render(
    <MemoryRouter>
      <SameFlowPanel invId="inv-wmi" verdict={verdict} />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('the same-flow block of a report', () => {
  it('names the siblings, their verdicts, and links each report', async () => {
    vi.mocked(getInvestigationSiblings).mockResolvedValue({
      siblings: [sib(), sib({ name: GEO, verdict: 'untriaged', invId: null, signals: ['flow'] })],
      siblingCount: 2,
      reason: null,
    });
    renderPanel();
    const panel = await screen.findByTestId('same-flow-panel');
    expect(getInvestigationSiblings).toHaveBeenCalledWith('inv-wmi');
    const rows = within(panel).getAllByTestId('same-flow-sibling');
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain(NTLM);
    expect(rows[0].textContent).toContain('False positive');
    expect(rows[0].textContent).toContain('Same two hosts within 5 minutes');
    const link = within(rows[0]).getByRole('link', { name: `Open the report of ${NTLM}` });
    expect(link.getAttribute('href')).toBe('/investigation/inv-ntlm');
    expect(rows[1].textContent).toContain('Untriaged');
    expect(rows[1].textContent).toContain('Same community ID within 1 hour');
    expect(panel.textContent).toContain(
      'Another detection shares this flow when one of its alerts has the same community ID within 1 hour of this alert.',
    );
    // An untriaged sibling has no report. Show is its way to the alerts.
    expect(within(rows[1]).queryByRole('link', { name: /Open the report/ })).toBeNull();
    expect(within(rows[1]).getByRole('link', { name: `Show ${GEO} in Alerts` })).toBeTruthy();
  });

  it('says so when the opposite verdict shares the flow', async () => {
    vi.mocked(getInvestigationSiblings).mockResolvedValue({ siblings: [sib()], siblingCount: 1, reason: null });
    renderPanel('true_positive');
    const panel = await screen.findByTestId('same-flow-panel');
    expect(panel.textContent).toContain('A false positive shares this flow.');
    expect(panel.getAttribute('data-tone')).toBe('warning');
  });

  it('NEGATIVE CONTROL: verdicts that agree keep the neutral tone', async () => {
    vi.mocked(getInvestigationSiblings).mockResolvedValue({ siblings: [sib()], siblingCount: 1, reason: null });
    renderPanel('false_positive');
    const panel = await screen.findByTestId('same-flow-panel');
    expect(panel.getAttribute('data-tone')).toBe('neutral');
    expect(panel.textContent).not.toContain('shares this flow.');
  });

  it('names the siblings the list leaves out', async () => {
    vi.mocked(getInvestigationSiblings).mockResolvedValue({ siblings: [sib()], siblingCount: 4, reason: null });
    renderPanel();
    expect((await screen.findByTestId('same-flow-panel')).textContent).toContain('3 more detections share this flow.');
  });

  it('Show opens the Alerts row of an untriaged sibling (V3 interaction)', async () => {
    // An untriaged sibling has no report, and the block gave no way to reach it.
    vi.mocked(getInvestigationSiblings).mockResolvedValue({
      siblings: [sib({ name: GEO, verdict: 'untriaged', invId: null, signals: ['flow'] })],
      siblingCount: 1,
      reason: null,
      partial: false,
      windowFrom: '2026-09-03T19:48:48+00:00',
      windowTo: '2026-09-05T19:48:48+00:00',
    });
    renderPanel();
    const panel = await screen.findByTestId('same-flow-panel');
    const show = within(panel).getByRole('link', { name: `Show ${GEO} in Alerts` });
    const href = new URL(show.getAttribute('href') as string, 'http://console.test');
    expect(href.pathname).toBe('/alerts');
    expect(href.searchParams.get('show')).toBe(`suricata:${GEO}`);
    expect(href.searchParams.get('hide_acked')).toBe('false');
    expect(href.searchParams.get('range')).toBe('custom');
    // The window holds the whole read: it starts at or before the read and
    // ends at or after it.
    expect(new Date(href.searchParams.get('from') as string).getTime()).toBeLessThanOrEqual(
      Date.parse('2026-09-03T19:48:48Z'),
    );
    expect(new Date(href.searchParams.get('to') as string).getTime()).toBeGreaterThanOrEqual(
      Date.parse('2026-09-05T19:48:48Z'),
    );
  });

  it('NEGATIVE CONTROL: an older server with no window opens the 30 day list', () => {
    const href = new URL(siblingRowHref(sib(), null, null), 'http://console.test');
    expect(href.searchParams.get('range')).toBe('30d');
    expect(href.searchParams.get('from')).toBeNull();
    expect(href.searchParams.get('show')).toBe(`suricata:${NTLM}`);
  });

  it('Show calls the screen when the report sits in the Alerts drawer', async () => {
    vi.mocked(getInvestigationSiblings).mockResolvedValue({ siblings: [sib()], siblingCount: 1, reason: null });
    const onShow = vi.fn();
    render(
      <MemoryRouter>
        <SameFlowPanel invId="inv-wmi" verdict="true_positive" onShow={onShow} />
      </MemoryRouter>,
    );
    const panel = await screen.findByTestId('same-flow-panel');
    expect(within(panel).queryByRole('link', { name: `Show ${NTLM} in Alerts` })).toBeNull();
    fireEvent.click(within(panel).getByRole('button', { name: `Show ${NTLM} in Alerts` }));
    expect(onShow).toHaveBeenCalledWith(expect.objectContaining({ name: NTLM, kind: 'suricata' }));
  });

  it('says the count is a floor when the read listed fewer groups than the flow holds', async () => {
    vi.mocked(getInvestigationSiblings).mockResolvedValue({
      siblings: [sib()],
      siblingCount: 1,
      reason: null,
      partial: true,
    });
    renderPanel();
    const panel = await screen.findByTestId('same-flow-panel');
    expect(panel.textContent).toContain('At least 1 other detection shares the flow of this alert.');
    expect(panel.textContent).toContain('The list can be partial.');
  });

  it('NEGATIVE CONTROL: a whole read states the exact count', async () => {
    vi.mocked(getInvestigationSiblings).mockResolvedValue({ siblings: [sib()], siblingCount: 1, reason: null, partial: false });
    renderPanel();
    const panel = await screen.findByTestId('same-flow-panel');
    expect(panel.textContent).toContain('1 other detection shares the flow of this alert.');
    expect(panel.textContent).not.toContain('At least');
    expect(panel.textContent).not.toContain('partial');
  });

  it.each([
    ['no sibling', { siblings: [], siblingCount: 0, reason: null }],
    ['no alert', { siblings: null, siblingCount: null, reason: 'no_alert' as const }],
    ['no grid answer', { siblings: null, siblingCount: null, reason: 'grid' as const }],
  ])('NEGATIVE CONTROL: %s draws no block', async (_label, answer) => {
    vi.mocked(getInvestigationSiblings).mockResolvedValue(answer);
    renderPanel();
    await waitFor(() => expect(getInvestigationSiblings).toHaveBeenCalled());
    await Promise.resolve();
    expect(screen.queryByTestId('same-flow-panel')).toBeNull();
  });

  it('NEGATIVE CONTROL: a failed request draws no block', async () => {
    vi.mocked(getInvestigationSiblings).mockRejectedValue(new Error('offline'));
    renderPanel();
    await waitFor(() => expect(getInvestigationSiblings).toHaveBeenCalled());
    expect(screen.queryByTestId('same-flow-panel')).toBeNull();
  });
});
