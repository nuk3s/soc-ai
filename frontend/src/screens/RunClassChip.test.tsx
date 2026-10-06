// The budget class chip (stage 1, item 2). A run carries its class: cheap,
// standard, deep or rule prior. The Investigations list, the drawer and the
// page show it as a small chip with a one-sentence tooltip. A run stored
// before the classes existed carries none and shows nothing: an absent chip
// says "not recorded", and a guessed chip would be a false statement.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { RunClassChip } from '../components/Badges';
import { CHIP_RUN_CLASS, ORACLE_REASON } from '../lib/tooltips';
import type { Investigation as Inv, InvestigationList, InvestigationRow } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations: vi.fn(),
  listSavedViews: vi.fn().mockResolvedValue([]),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
}));

import { listInvestigations } from '../lib/api';
import { Investigation } from './Investigation';
import { Investigations } from './Investigations';

const invRow = (over: Partial<InvestigationRow>): InvestigationRow => ({
  id: 'INV-1',
  name: 'ET INFO STUN Binding Request',
  kind: 'suricata',
  verdict: 'false_positive',
  conf: 0.88,
  host: '192.0.2.10',
  dst: '198.51.100.7',
  status: 'complete',
  when: '2h ago',
  ts: '2026-10-04T00:00:00+00:00',
  alertId: 'ev-1',
  isPrimary: true,
  fallback: false,
  ...over,
});

const invList = (rows: InvestigationRow[]): InvestigationList => ({
  rows,
  total: rows.length,
  running: 0,
  truePositives: 0,
  totalAll: rows.length,
  active: false,
  limit: 50,
  offset: 0,
});

const invDetail = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET INFO STUN Binding Request',
    kind: 'suricata',
    host: '192.0.2.10',
    ip: '198.51.100.7',
    verdict: 'false_positive',
    conf: 0.88,
    rationale: 'STUN keepalive.',
    summary: [{ t: 'text', v: 'keepalive' }],
    status: 'complete',
    elapsedLabel: '8s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

beforeEach(() => {
  vi.mocked(listInvestigations).mockResolvedValue(invList([]));
});

describe('RunClassChip', () => {
  it.each(['cheap', 'standard', 'deep', 'rule_prior'])('names the %s class with its tooltip', (cls) => {
    render(<RunClassChip runClass={cls} />);
    const chip = screen.getByTestId('run-class-chip');
    expect(chip).toHaveTextContent(CHIP_RUN_CLASS[cls].label);
    expect(chip).toHaveAttribute('title', CHIP_RUN_CLASS[cls].title);
  });

  it('renders nothing for a run with no recorded class', () => {
    const { container } = render(<RunClassChip runClass={null} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing for a class this build does not know', () => {
    const { container } = render(<RunClassChip runClass="turbo" />);
    expect(container).toBeEmptyDOMElement();
  });

  it('writes every tooltip in plain sentences with no dash', () => {
    for (const { title } of Object.values(CHIP_RUN_CLASS)) {
      expect(title).not.toMatch(/[–—]/);
      for (const sentence of title.split('. ')) {
        expect(sentence.split(/\s+/).length).toBeLessThanOrEqual(25);
      }
    }
  });
});

describe('Investigations list: run class chip', () => {
  it('shows the class of each row', async () => {
    vi.mocked(listInvestigations).mockResolvedValue(
      invList([invRow({ runClass: 'rule_prior' })]),
    );
    render(
      <MemoryRouter initialEntries={['/investigations']}>
        <Investigations />
      </MemoryRouter>,
    );
    await screen.findByText('ET INFO STUN Binding Request');
    const chip = screen.getByTestId('run-class-INV-1');
    expect(chip).toHaveTextContent('rule prior');
    expect(chip).toHaveAttribute('title', CHIP_RUN_CLASS.rule_prior.title);
  });

  it('shows no chip on a row stored before the classes existed', async () => {
    vi.mocked(listInvestigations).mockResolvedValue(invList([invRow({ runClass: null })]));
    render(
      <MemoryRouter initialEntries={['/investigations']}>
        <Investigations />
      </MemoryRouter>,
    );
    await screen.findByText('ET INFO STUN Binding Request');
    expect(screen.queryByTestId('run-class-INV-1')).toBeNull();
  });
});

describe('Investigation drawer and page: run class chip', () => {
  it.each(['drawer', 'page'] as const)('shows the class beside the verdict in the %s', (layout) => {
    render(
      <MemoryRouter>
        <Investigation inv={invDetail({ runClass: 'cheap' })} layout={layout} />
      </MemoryRouter>,
    );
    expect(screen.getByTestId('run-class-chip')).toHaveTextContent('cheap');
  });

  it('keeps the class on a run that failed before its verdict', () => {
    render(
      <MemoryRouter>
        <Investigation inv={invDetail({ runClass: 'deep', status: 'error' })} layout="page" />
      </MemoryRouter>,
    );
    expect(screen.getByTestId('run-class-chip')).toHaveTextContent('deep');
  });

  it('says in a sentence why the verdict went to the Oracle', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={invDetail({
            runClass: 'standard',
            oracle: { escalated: true, reason: 'template_split', localVerdict: 'true_positive' },
          })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.getByText(ORACLE_REASON.template_split)).toBeInTheDocument();
  });

  it('says in a sentence why the classic rule sent the verdict', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={invDetail({ oracle: { escalated: true, reason: 'malware_non_tp' } })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.getByText(ORACLE_REASON.malware_non_tp)).toBeInTheDocument();
  });

  it('shows an unknown escalation code as it was stored', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={invDetail({ oracle: { escalated: true, reason: 'retired_reason_code' } })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.getByText('retired_reason_code')).toBeInTheDocument();
  });

  it('shows no chip when the run has no recorded class', () => {
    render(
      <MemoryRouter>
        <Investigation inv={invDetail({ runClass: undefined })} layout="page" />
      </MemoryRouter>,
    );
    expect(screen.queryByTestId('run-class-chip')).toBeNull();
  });
});
