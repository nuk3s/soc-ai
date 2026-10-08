// The hunt map answers two questions: how the entities in the findings
// connect, and which link a threat finding sits on. Each test pins one part of
// the answer in the shaped data, before anything draws.
import { describe, expect, it } from 'vitest';
import { findingNodeId, HUNT_COLOR, hostNodeId, huntGraphView, MAX_MAP_HOSTS } from './huntGraph';
import { SEVERITY } from './tokens';
import type { HuntFinding } from './types';

function finding(o: Partial<HuntFinding> = {}): HuntFinding {
  return { title: 'f', detail: '', severity: 'info', hosts: [], citations: [], ...o };
}

const LONG_TITLE =
  'Kerberos replication request from a workstation that is not a domain controller';

const FINDINGS: HuntFinding[] = [
  finding({
    title: LONG_TITLE,
    severity: 'high',
    category: 'threat',
    hosts: ['192.168.10.20', '198.51.100.7'],
    citations: ['d1', 'd2', 'd3', 'd4'],
  }),
  finding({ title: 'No EDR coverage', severity: 'medium', category: 'visibility_gap', hosts: ['192.168.10.20'], citations: ['d5'] }),
  finding({ title: 'DNS lookups', severity: 'low', category: 'observation', hosts: [] }),
];

describe('huntGraphView: how the entities connect', () => {
  it('draws each finding and each host it names, joined by a line', () => {
    const map = huntGraphView(FINDINGS, ['files-01']);
    const ids = map.view.nodes.map((n) => n.id);
    expect(ids).toEqual([
      findingNodeId(0),
      findingNodeId(1),
      findingNodeId(2),
      hostNodeId('192.168.10.20'),
      hostNodeId('198.51.100.7'),
      hostNodeId('files-01'),
    ]);
    expect(map.view.edges.map((e) => [e.source, e.target])).toEqual([
      [findingNodeId(0), hostNodeId('192.168.10.20')],
      [findingNodeId(0), hostNodeId('198.51.100.7')],
      [findingNodeId(1), hostNodeId('192.168.10.20')],
    ]);
    expect(map.findings).toBe(3);
    expect(map.hosts).toBe(3);
    expect(map.hostsCut).toBe(0);
    expect(map.view.layout).toEqual({ mode: 'force' });
  });

  it('grows a host that more findings name', () => {
    const nodes = Object.fromEntries(huntGraphView(FINDINGS).view.nodes.map((n) => [n.id, n]));
    expect(nodes[hostNodeId('192.168.10.20')].size).toBeGreaterThan(nodes[hostNodeId('198.51.100.7')].size);
    expect(nodes[hostNodeId('192.168.10.20')].lines[1].text).toBe('2 findings');
  });

  it('widens a line by the documents its finding cites', () => {
    const edges = huntGraphView(FINDINGS).view.edges;
    expect(edges[0].width).toBeGreaterThan(edges[2].width);
  });

  it('colours a host by its role', () => {
    const nodes = Object.fromEntries(huntGraphView(FINDINGS, ['files-01']).view.nodes.map((n) => [n.id, n]));
    expect(nodes[hostNodeId('192.168.10.20')].color).toBe(HUNT_COLOR.internal);
    expect(nodes[hostNodeId('198.51.100.7')].color).toBe(HUNT_COLOR.external);
    // Affected, and no finding names it: grey and dim.
    expect(nodes[hostNodeId('files-01')].color).toBe(HUNT_COLOR.unnamed);
    expect(nodes[hostNodeId('files-01')].dim).toBe(true);
    expect(nodes[hostNodeId('files-01')].lines[1].text).toBe('no finding names it');
  });

  it('opens a host page through the entity link logic, and a finding opens nothing', () => {
    const nodes = Object.fromEntries(huntGraphView(FINDINGS, ['files-01']).view.nodes.map((n) => [n.id, n]));
    expect(nodes[hostNodeId('198.51.100.7')].href).toBe('/entity/198.51.100.7');
    expect(nodes[hostNodeId('files-01')].href).toBe('/entity/files-01');
    expect(nodes[findingNodeId(0)].href).toBeUndefined();
  });

  it('shows a long finding title whole, over several lines', () => {
    const f1 = huntGraphView(FINDINGS).view.nodes[0];
    expect(f1.glyph).toBe('F1');
    const titleLines = f1.lines.filter((l) => l.tone === 'primary').map((l) => l.text);
    expect(titleLines.length).toBeGreaterThan(1);
    expect(titleLines.join(' ')).toBe(LONG_TITLE);
    expect(f1.lines.map((l) => l.text).join(' ')).not.toMatch(/…|\.\.\./);
  });
});

describe('huntGraphView: the threat finding', () => {
  it('draws the threat finding in its severity colour and its lines in red', () => {
    const map = huntGraphView(FINDINGS);
    expect(map.view.nodes[0].color).toBe(SEVERITY.high.color);
    expect(map.view.nodes[1].color).toBe(HUNT_COLOR.gap);
    expect(map.view.nodes[2].color).toBe(HUNT_COLOR.observation);
    const red = map.view.edges.filter((e) => e.threat);
    expect(red.length).toBe(2);
    expect(red.every((e) => e.source === findingNodeId(0) && e.color === HUNT_COLOR.threat)).toBe(true);
    expect(map.view.legend.some((l) => l.label === 'a threat finding names this host')).toBe(true);
  });

  it('negative control: no threat finding, no red line', () => {
    const calm = FINDINGS.map((f) => ({ ...f, category: 'observation' }));
    const map = huntGraphView(calm);
    expect(map.view.edges.some((e) => e.threat || e.color === HUNT_COLOR.threat)).toBe(false);
    expect(map.view.legend.some((l) => l.label === 'a threat finding names this host')).toBe(false);
  });

  it('reads a finding with no category as a threat, as the backend does', () => {
    const map = huntGraphView([finding({ severity: 'medium', hosts: ['192.168.10.20'] })]);
    expect(map.view.edges[0].threat).toBe(true);
  });
});

describe('huntGraphView: nothing to draw, and too much', () => {
  it('draws nothing when no finding names a host and none is affected', () => {
    const map = huntGraphView([finding({ title: 'gap', category: 'visibility_gap' })]);
    expect(map.view.nodes).toEqual([]);
    expect(map.hosts).toBe(0);
  });

  it('dims a finding that names no host on the map', () => {
    const f3 = huntGraphView(FINDINGS).view.nodes[2];
    expect(f3.dim).toBe(true);
    expect(f3.tooltip).toContain('Names no host.');
  });

  it('draws at most MAX_MAP_HOSTS hosts and says how many it left off', () => {
    const many = Array.from({ length: MAX_MAP_HOSTS + 50 }, (_, i) =>
      finding({ title: `f${i}`, category: 'threat', hosts: [`host-${String(i).padStart(3, '0')}`] }),
    );
    const map = huntGraphView(many);
    expect(map.hosts).toBe(MAX_MAP_HOSTS);
    expect(map.hostsCut).toBe(50);
    const drawnHosts = map.view.nodes.filter((n) => n.id.startsWith('host:'));
    expect(drawnHosts.length).toBe(MAX_MAP_HOSTS);
    // No edge points at a host the map left off.
    const ids = new Set(map.view.nodes.map((n) => n.id));
    expect(map.view.edges.every((e) => ids.has(e.target))).toBe(true);
  });
});
