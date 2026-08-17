// Two predicates that decide where an address-shaped URL segment goes, and what
// a peer node on the host graph is drawn as. Both are load-bearing enough to be
// pinned on their own: `isIpKey` alone decides whether /entity/:value keeps
// rendering Entity, and getting `isPrivateIp` wrong sends an analyst to a page
// that structurally cannot answer.
import { describe, expect, it } from 'vitest';
import { isIpKey, isPrivateIp } from './ip';

describe('isIpKey', () => {
  it('accepts the address families the dossier is keyed on', () => {
    // The server normalizes through Python's `ipaddress`, which takes both.
    expect(isIpKey('192.0.2.10')).toBe(true);
    expect(isIpKey('2001:db8::1')).toBe(true);
    expect(isIpKey('::1')).toBe(true);
  });

  it('rejects everything a hostname can be', () => {
    expect(isIpKey('example.com')).toBe(false);
    expect(isIpKey('workstation-04')).toBe(false);
    expect(isIpKey('')).toBe(false);
    expect(isIpKey('   ')).toBe(false);
    // The em-dash placeholder that shipped `/entity/%E2%80%94` once already.
    expect(isIpKey('—')).toBe(false);
  });

  it('rejects an octet that is not a byte', () => {
    expect(isIpKey('192.0.2.999')).toBe(false);
    expect(isIpKey('1.2.3')).toBe(false);
    expect(isIpKey('1.2.3.4.5')).toBe(false);
  });

  it('rejects leading zeros rather than silently re-reading them', () => {
    // `010.0.0.1` is not what `ipaddress` accepts, so treating it as an address
    // would route the analyst INTO the dossier's 404 card — the opposite of the
    // bias this predicate is supposed to have.
    expect(isIpKey('010.0.0.1')).toBe(false);
    expect(isIpKey('192.168.001.1')).toBe(false);
    // A bare zero octet is still a byte.
    expect(isIpKey('10.0.0.1')).toBe(true);
  });
});

describe('isPrivateIp', () => {
  it('recognises the RFC1918 space a host dossier can exist in', () => {
    expect(isPrivateIp('10.0.0.1')).toBe(true);
    expect(isPrivateIp('192.168.10.202')).toBe(true);
    expect(isPrivateIp('172.16.0.1')).toBe(true);
    expect(isPrivateIp('172.31.255.254')).toBe(true);
    expect(isPrivateIp('169.254.1.1')).toBe(true);
    expect(isPrivateIp('127.0.0.1')).toBe(true);
    expect(isPrivateIp('fd00::1')).toBe(true);
    expect(isPrivateIp('fe80::1')).toBe(true);
  });

  it('does not over-claim the 172 range', () => {
    // 172.15 and 172.32 are public; only 172.16-31 is private, and an off-by-one
    // here silently changes which page an analyst lands on.
    expect(isPrivateIp('172.15.0.1')).toBe(false);
    expect(isPrivateIp('172.32.0.1')).toBe(false);
  });

  it('calls public space public', () => {
    expect(isPrivateIp('8.8.8.8')).toBe(false);
    expect(isPrivateIp('198.51.100.7')).toBe(false);
    expect(isPrivateIp('203.0.113.9')).toBe(false);
    expect(isPrivateIp('2001:db8::1')).toBe(false);
    // Not an address at all is not private either.
    expect(isPrivateIp('example.com')).toBe(false);
  });
});
