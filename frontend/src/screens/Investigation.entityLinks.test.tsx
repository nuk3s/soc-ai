// Every host, user, domain and address the investigation page names is a link
// to its page (dogfood 2026-10-06, hosts F1). The page named all of them as
// plain text. The negative controls: a version number and a word that holds
// a host name are not entities.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
}));

import { Investigation, splitEntities } from './Investigation';

const inv = (over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'Grid Node Login Failure (SSH)',
    kind: 'sigma',
    host: '192.0.2.226',
    ip: '—',
    srcIp: '192.0.2.226',
    dstIp: '198.51.100.7',
    reportedBy: 'gridnode',
    verdict: 'false_positive',
    conf: 0.68,
    rationale: 'A failed login from 192.0.2.226 to gridnode by svc_backup.',
    summary: [{ t: 'text', v: 'The address 192.0.2.226 failed once. Version 1.2.3 runs.' }],
    status: 'complete',
    elapsedLabel: '1m 5s',
    actions: [],
    timeline: [],
    nodes: [{ id: 'n1', x: 0, y: 0, kind: 'host', label: '192.0.2.226' }],
    edges: [],
    seedChat: [],
    alert: { rule: 'Grid Node Login Failure', src: '192.0.2.226', dst: '198.51.100.7', proto: 'tcp', action: 'allowed', count: 1 },
    entities: [
      { value: '192.0.2.226', type: 'address', role: 'source', host_key: 'agent:a1', href: '/hosts/agent:a1' },
      { value: 'gridnode', type: 'host', role: 'reporter', host_key: 'agent:g1', href: '/hosts/agent:g1' },
      { value: 'svc_backup', type: 'user', role: 'lead', host_key: null, href: '/entity/svc_backup?type=user' },
    ],
    ...over,
  }) as Inv;

const mount = (i: Inv) =>
  render(
    <MemoryRouter>
      <Investigation inv={i} layout="page" />
    </MemoryRouter>,
  );

describe('entity links on the investigation page', () => {
  it('links both ends and the reporter in the header', () => {
    mount(inv());
    const chip = screen.getByTestId('verdict-endpoints');
    expect(within(chip).getByTestId('endpoint-src').querySelector('a')?.getAttribute('href')).toBe(
      '/hosts/agent%3Aa1',
    );
    // No machine known for the destination: the entity page answers for it.
    expect(within(chip).getByTestId('endpoint-dst').querySelector('a')?.getAttribute('href')).toBe(
      '/entity/198.51.100.7',
    );
    expect(within(chip).getByTestId('endpoint-on').querySelector('a')?.getAttribute('href')).toBe(
      '/hosts/agent%3Ag1',
    );
    // The text of the chip is unchanged.
    expect(chip.textContent).toBe('192.0.2.226 → 198.51.100.7 on gridnode');
  });

  it('links the entities the rationale names, a user among them', () => {
    mount(inv());
    const links = screen.getAllByTestId('entity-link').map((a) => a.getAttribute('href'));
    expect(links).toContain('/entity/svc_backup?type=user');
  });

  it('links the source and the destination in Alert details', () => {
    mount(inv());
    const hrefs = screen.getAllByTestId('entity-link').map((a) => a.getAttribute('href'));
    expect(hrefs.filter((h) => h === '/entity/198.51.100.7').length).toBeGreaterThanOrEqual(2);
  });

  it('lists the entities of the entity scope as links', () => {
    mount(inv());
    const row = screen.getByTestId('entity-scope-links');
    expect(within(row).getAllByTestId('entity-link').map((a) => a.textContent)).toEqual([
      '192.0.2.226',
      'gridnode',
      'svc_backup',
    ]);
  });

  it('does not take a version number or a longer word for an entity', () => {
    const segs = splitEntities('Version 1.2.3 on gridnodes and 10.0.0.1.', [
      { value: 'gridnode', type: 'host', role: '', host_key: null, href: '' },
    ]);
    expect(segs.filter((s) => s.t === 'entity').map((s) => s.v)).toEqual(['10.0.0.1']);
  });
});
