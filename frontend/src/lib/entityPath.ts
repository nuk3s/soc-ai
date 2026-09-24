import { isIpKey } from './ip';

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

/** The in-app path for one entity. Only an address reaches the host page. */
export function entityPath(kind: string | null | undefined, key: string): string {
  if (kind === 'host' && isIpKey(key)) return `/hosts/${encodeURIComponent(key)}`;
  return `/entity/${encodeURIComponent(key)}`;
}
