// A citation opens the document (K1, review 2026-11-12, console finding 6).
// Run 01M75Z171G67H80T26KTR9HPTQ cited "alert.payload_printable" and
// "community_id_events.0.zeek_http_status". Each chip was a span with a
// tooltip, a click did nothing, and the payload was not on the page.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getEvent: vi.fn(),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
}));

import { getEvent } from '../lib/api';
import { ShellProvider } from '../shell/ShellContext';
import { Investigation } from './Investigation';

const ZEEK_ID = 'ZeekDoc00000000000001';
const ALERT_ID = 'AlertDoc0000000000001';

const inv = (over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET EXPLOIT PHP php2shell',
    kind: 'suricata',
    host: '10.20.30.5',
    ip: '10.40.50.7',
    verdict: 'true_positive',
    conf: 0.75,
    rationale: 'The captured payload confirms the exploit that the rule names.',
    summary: [{ t: 'text', v: 'Host 10.20.30.5 sent a POST to 10.40.50.7.' }],
    status: 'complete',
    elapsedLabel: '3m',
    actions: [],
    timeline: [
      { id: 'e4', group: 'Tool calls', title: 'Indicator prevalence: rare', time: '', detail: '', tool: 't_prevalence' },
    ],
    nodes: [],
    edges: [],
    seedChat: [],
    citations: [
      { text: ALERT_ID, kind: 'id', target: ALERT_ID, resolved: true },
      {
        text: 'community_id_events.0.zeek_http_status',
        kind: 'path',
        target: 'community_id_events.0.zeek_http_status',
        resolved: true,
        documentId: ZEEK_ID,
        value: '200',
      },
      {
        text: 'alert.payload_printable',
        kind: 'path',
        target: 'alert.payload_printable',
        resolved: true,
        documentId: ALERT_ID,
        value: 'POST /index.php HTTP/1.1\nContent-Disposition: form-data',
      },
      { text: 'alert.alert.alert_action', kind: 'path', target: 'alert.alert.alert_action', resolved: null },
      { text: 'tool t_prevalence', kind: 'tool', target: 't_prevalence', resolved: true },
      { text: 'tool t_origin_chain', kind: 'tool', target: 't_origin_chain', resolved: true },
    ],
    ...over,
  }) as Inv;

const mount = (i: Inv) =>
  render(
    <ShellProvider>
      <MemoryRouter>
        <Investigation inv={i} layout="page" />
      </MemoryRouter>
    </ShellProvider>,
  );

const chip = (name: string) =>
  within(screen.getByTestId('cited-evidence')).getByText(name, { exact: true });

beforeEach(() => {
  vi.mocked(getEvent)
    .mockReset()
    .mockImplementation(async (id: string) => ({
      id,
      dataset: id === ZEEK_ID ? 'zeek.http' : 'suricata.alert',
      timestamp: '2026-11-11T18:45:34Z',
      source:
        id === ZEEK_ID
          ? { http: { status_code: 200, method: 'POST' }, network: { transport: 'tcp' } }
          : { payload_printable: 'POST /index.php HTTP/1.1', rule: { name: 'ET EXPLOIT' } },
    }));
});

describe('a cited field', () => {
  it('reads in words with its value and keeps the raw path in the tooltip', () => {
    mount(inv());
    const status = chip('HTTP status 200');
    expect(status.tagName).toBe('BUTTON');
    expect(status.getAttribute('title')).toContain('community_id_events.0.zeek_http_status');
    expect(chip('Payload').tagName).toBe('BUTTON');
    expect(screen.getByTestId('cited-evidence').textContent).not.toContain('zeek_http_status');
  });

  it('opens the session event at the field with its value', async () => {
    mount(inv());
    fireEvent.click(chip('HTTP status 200'));
    await waitFor(() => expect(getEvent).toHaveBeenCalledWith(ZEEK_ID));
    expect(screen.getByTestId('document-cited').textContent).toContain('HTTP status');
    expect(screen.getByTestId('document-cited-value').textContent).toBe('200');
    await waitFor(() => expect(document.querySelector('[data-cited="true"]')?.textContent).toContain('http.status_code'));
  });

  it('opens the alert at the payload and shows the whole payload', async () => {
    mount(inv());
    fireEvent.click(chip('Payload'));
    await waitFor(() => expect(getEvent).toHaveBeenCalledWith(ALERT_ID));
    expect(screen.getByTestId('document-cited-value').textContent).toContain('Content-Disposition: form-data');
    // Control: a whole value carries no cut line.
    expect(screen.queryByTestId('document-cited-cut')).toBeNull();
  });

  it('states under a value the server cut that it is cut at 2,000 characters', async () => {
    const big = 'A'.repeat(2000);
    mount(
      inv({
        citations: [
          {
            text: 'alert.payload_printable',
            kind: 'path',
            target: 'alert.payload_printable',
            resolved: true,
            documentId: ALERT_ID,
            value: big,
            valueTruncated: true,
          },
        ],
      }),
    );
    fireEvent.click(chip('Payload'));
    await waitFor(() => expect(getEvent).toHaveBeenCalledWith(ALERT_ID));
    expect(screen.getByTestId('document-cited-value').textContent).toBe(big);
    expect(screen.getByTestId('document-cited-cut').textContent).toBe('The value is cut at 2,000 characters.');
  });

  it('control: a field no stored document holds stays a plain chip that says so', () => {
    mount(inv());
    const plain = chip('Alert action');
    expect(plain.tagName).toBe('SPAN');
    expect(plain.getAttribute('title')).toContain('opens nothing');
    fireEvent.click(plain);
    expect(getEvent).not.toHaveBeenCalled();
  });
});

describe('a cited document and a cited tool', () => {
  it('a document id opens the document', async () => {
    mount(inv());
    fireEvent.click(within(screen.getByTestId('cited-evidence')).getByRole('button', { name: ALERT_ID }));
    await waitFor(() => expect(getEvent).toHaveBeenCalledWith(ALERT_ID));
    expect(screen.queryByTestId('document-cited')).toBeNull();
  });

  it('a tool with a step in the timeline is a control', () => {
    mount(inv());
    const tool = chip('prevalence check');
    expect(tool.tagName).toBe('BUTTON');
    expect(tool.getAttribute('title')).toContain('t_prevalence');
  });

  it('control: a tool with no step stays a plain chip', () => {
    mount(inv());
    const tool = chip('origin chain');
    expect(tool.tagName).toBe('SPAN');
    expect(tool.getAttribute('title')).toContain('no step');
  });
});
