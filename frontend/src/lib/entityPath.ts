import { machineHref } from './hostsList';
import { isIpKey } from './ip';
import type { EntityType } from './types';

// ---------------------------------------------------------------------------
// Where one entity's page lives.
//
// The host dossier is keyed on an IP address. The server normalizes the key
// through Python's `ipaddress` and 404s anything else, so a user account sent
// to /hosts/<name> landed on a card that says the network sweep has never seen
// this host. That is a false answer about a real account.
//
// Every surface that names an entity reads this, so one entity opens the same
// page wherever an analyst meets it.
// ---------------------------------------------------------------------------

/** The in-app path for one entity. Only an address reaches the host page.
 *  A user carries its type, so a user that shares a name with a machine
 *  opens the user. */
export function entityPath(kind: string | null | undefined, key: string): string {
  if (kind === 'host' && isIpKey(key)) return `/hosts/${encodeURIComponent(key)}`;
  if (kind === 'user') return `/entity/${encodeURIComponent(key)}?type=user`;
  return `/entity/${encodeURIComponent(key)}`;
}

/**
 * The page that answers "who is this" for one value.
 *
 * - A machine opens its page. With `hostKey` the link goes there in one step.
 * - Any other value opens the entity page. That page resolves the value: a
 *   name or an address a machine holds moves on to the machine page, and an
 *   address no machine holds stays on the entity page. The full Hosts list
 *   is never the answer (dogfood 2026-10-06, S2).
 * - A user and a domain carry their type, so a name a machine shares never
 *   opens the machine.
 */
export function entityHref(
  value: string,
  type?: EntityType | string | null,
  hostKey?: string | null,
): string {
  const v = value.trim();
  if (hostKey && type !== 'user' && type !== 'domain') return machineHref(hostKey);
  const hint = type === 'user' || type === 'domain' ? `?type=${type}` : '';
  return `/entity/${encodeURIComponent(v)}${hint}`;
}

/** The type of a value when the caller does not know it: an address or a
 *  host name. */
export function guessEntityType(value: string): EntityType {
  return isIpKey(value) ? 'address' : 'host';
}
