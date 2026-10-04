// The machine words both host screens share: the role with its state, the
// name source, the address type, and the machine key shape.
import { describe, expect, it } from 'vitest';
import {
  addressKindLabel,
  hoursAge,
  identitySentence,
  isMachineKey,
  machineRoleView,
  nameSourceLabel,
  sentenceText,
} from './hostDossier';
import type { DossierFieldBrief, MachineRole } from './types';

const role = (over: Partial<MachineRole>): MachineRole => ({
  value: null,
  label: null,
  confidence: null,
  state: 'unknown',
  guess: null,
  stale_hours: null,
  ...over,
});

describe('machineRoleView', () => {
  it('names a declared and an inferred role with the state beside it', () => {
    const declared = machineRoleView(role({ value: 'domain_controller', label: 'domain controller', state: 'declared' }));
    expect(declared).toMatchObject({ text: 'domain controller', note: 'declared', accent: 'domain_controller' });
    const inferred = machineRoleView(role({ value: 'network_device', state: 'inferred' }));
    expect(inferred).toMatchObject({ text: 'network device', note: 'inferred' });
  });

  it('says "low confidence: <guess>" and gives a guess no role colour', () => {
    const v = machineRoleView(role({ state: 'low_confidence', guess: 'hypervisor', confidence: 0.4 }));
    expect(v.text).toBe('low confidence: hypervisor');
    expect(v.accent).toBeNull();
  });

  it('says "stale <age>" with the guess', () => {
    expect(machineRoleView(role({ state: 'stale', guess: 'iot', stale_hours: 200 })).text).toBe(
      'stale 8d: IoT device',
    );
    expect(machineRoleView(role({ state: 'stale', guess: 'server', stale_hours: 30 })).text).toBe(
      'stale 30h: server',
    );
    expect(machineRoleView(role({ state: 'stale' })).text).toBe('stale');
  });

  it('says "unknown" for an unknown role, and for no role at all', () => {
    expect(machineRoleView(role({})).text).toBe('unknown');
    expect(machineRoleView(null).text).toBe('unknown');
    // A declared state with no value is not an answer.
    expect(machineRoleView(role({ state: 'declared' })).text).toBe('unknown');
  });

  it('never prints a dash', () => {
    for (const state of ['declared', 'inferred', 'low_confidence', 'stale', 'unknown'] as const) {
      const v = machineRoleView(role({ state, value: 'server', guess: 'server', stale_hours: 5 }));
      expect(`${v.text} ${v.title}`).not.toMatch(/[–—]/);
    }
  });
});

describe('machine words', () => {
  it('recognises a machine key and nothing else', () => {
    expect(isMachineKey('agent:ea2db53b')).toBe(true);
    expect(isMachineKey('mac:aa:bb:cc:dd:ee:ff')).toBe(true);
    expect(isMachineKey('ip:192.0.2.10')).toBe(true);
    // An address, a MAC, a bare name and an IPv6 address are not keys.
    expect(isMachineKey('192.0.2.10')).toBe(false);
    expect(isMachineKey('aa:bb:cc:dd:ee:ff')).toBe(false);
    expect(isMachineKey('fd00::5')).toBe(false);
    expect(isMachineKey('web01')).toBe(false);
    expect(isMachineKey('agent:')).toBe(false);
  });

  it('spells the name source and the address type', () => {
    expect(nameSourceLabel('dhcp')).toBe('DHCP lease');
    expect(nameSourceLabel('agent')).toBe('agent');
    expect(nameSourceLabel(null)).toBeNull();
    expect(addressKindLabel('name')).toBe('DNS name');
    expect(addressKindLabel('network')).toBe('network');
  });

  it('formats an age in hours', () => {
    expect(hoursAge(0.2)).toBe('1h');
    expect(hoursAge(47)).toBe('47h');
    expect(hoursAge(72)).toBe('3d');
    expect(hoursAge(null)).toBeNull();
  });

  it('leads the identity sentence with the machine name when the page has one', () => {
    const fields: DossierFieldBrief[] = [];
    expect(sentenceText(identitySentence({ ip: '192.0.2.10', fields }, 'web01'))).toMatch(/^web01 /);
    expect(sentenceText(identitySentence({ ip: '192.0.2.10', fields }))).toMatch(/^192\.0\.2\.10 /);
  });
});
