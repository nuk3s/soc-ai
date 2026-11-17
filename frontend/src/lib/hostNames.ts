// The host name and role beside an address (J2, prod review 2026-11-12,
// ui-core 9). The lists showed "10.x.x.x → 10.y.y.y" while the Hosts page knew
// that one end was a named workstation and the other a server.
//
// One cache for the whole console. Each FlowBadge asks for its two addresses;
// the asks of one render pass go out as ONE read of /hosts/names, and a
// later render reads the cache. A list poll re-renders the rows and sends
// nothing until an entry ages out.
import { useEffect, useState } from 'react';
import { getHostNames, type HostName } from './api';
import { roleLabel } from './hostDossier';

/** An answer stays this long. */
const TTL_MS = 5 * 60_000;
/** A failed read is not asked again before this. */
const FAIL_TTL_MS = 60_000;
/** The server takes at most this many addresses in one read. */
const BATCH = 200;

interface Entry {
  at: number;
  ttl: number;
  value: HostName | null;
}

const cache = new Map<string, Entry>();
/** Queued or in flight. */
const pending = new Set<string>();
let queue: string[] = [];
let scheduled = false;
const listeners = new Set<() => void>();

const V4 = /^(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?$/;
const V6 = /^\[?([0-9a-f:]*:[0-9a-f:.]*)\]?$/i;

/** The bare address of a value, or null for a value that is not an address
 *  (a host name, the "—" placeholder). An IPv4 port is dropped. */
export function bareAddress(value: string | null | undefined): string | null {
  const v = (value ?? '').trim();
  const four = v.match(V4);
  if (four) return four[1];
  const six = v.match(V6);
  return six && six[1].includes(':') ? six[1] : null;
}

function fresh(ip: string): boolean {
  const e = cache.get(ip);
  return !!e && Date.now() - e.at < e.ttl;
}

/** Store the answers. True when a label changed, so a row must re-render. */
function store(ips: string[], hosts: Record<string, HostName> | null, ttl: number): boolean {
  const now = Date.now();
  let changed = false;
  for (const ip of ips) {
    const h = hosts?.[ip];
    const value = h && typeof h === 'object' ? h : null;
    if (hostLabelText(cache.get(ip)?.value ?? null) !== hostLabelText(value)) changed = true;
    cache.set(ip, { at: now, ttl, value });
  }
  return changed;
}

function flush() {
  scheduled = false;
  const batch = queue;
  queue = [];
  for (let i = 0; i < batch.length; i += BATCH) {
    const part = batch.slice(i, i + BATCH);
    getHostNames(part)
      .then((body) => {
        const hosts = body && typeof body.hosts === 'object' && body.hosts ? body.hosts : null;
        return store(part, hosts, hosts ? TTL_MS : FAIL_TTL_MS);
      })
      // A failed read keeps an older answer: the label does not flicker off.
      .catch(() => {
        const now = Date.now();
        for (const ip of part) {
          cache.set(ip, { at: now, ttl: FAIL_TTL_MS, value: cache.get(ip)?.value ?? null });
        }
        return false;
      })
      .then((changed) => {
        for (const ip of part) pending.delete(ip);
        if (changed) listeners.forEach((l) => l());
      });
  }
}

function want(values: (string | null | undefined)[]) {
  for (const value of values) {
    const ip = bareAddress(value);
    if (!ip || fresh(ip) || pending.has(ip)) continue;
    pending.add(ip);
    queue.push(ip);
  }
  if (queue.length && !scheduled) {
    scheduled = true;
    // After the effects of this render pass, so one read carries every row.
    queueMicrotask(flush);
  }
}

/** The machine of an address, from the cache. An aged entry still answers
 *  while its next read is in flight. */
export function hostOf(value: string | null | undefined): HostName | null {
  const ip = bareAddress(value);
  return ip ? cache.get(ip)?.value ?? null : null;
}

/** "name (role)", "name", "(role)", or null when the Hosts data has neither.
 *  A guessed role says so. */
export function hostLabelText(h: HostName | null): string | null {
  if (!h) return null;
  const name = h.name?.trim() || null;
  const role = h.role?.trim() ? `${roleLabel(h.role)}${h.roleGuess ? ', guess' : ''}` : null;
  if (name && role) return `${name} (${role})`;
  if (name) return name;
  if (role) return `(${role})`;
  return null;
}

/** Ask for the machines of `values`, and re-render when an answer lands. */
export function useHostNames(values: (string | null | undefined)[]): void {
  const [, setTick] = useState(0);
  useEffect(() => {
    const l = () => setTick((t) => t + 1);
    listeners.add(l);
    return () => {
      listeners.delete(l);
    };
  }, []);
  const key = values.map((v) => bareAddress(v) ?? '').join(',');
  useEffect(() => {
    want(key.split(','));
  }, [key]);
}

/** Test seam: forget every answer. */
export function resetHostNames(): void {
  cache.clear();
  pending.clear();
  queue = [];
  scheduled = false;
}
