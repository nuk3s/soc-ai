// ---------------------------------------------------------------------------
// Address-shape predicates.
//
// Both of these answer questions about a STRING, not about a host: whether a URL
// segment can name a dossier row, and whether an address is in the space the
// dossier census actually populates. They live together because the host page's
// routing gate needs both in one expression, and apart from each other they had
// already been written twice — once in App.tsx and once inside the peer graph.
// ---------------------------------------------------------------------------

/** One IPv4 octet: 0-255, and NOT zero-padded. `010` is not what Python's
 *  `ipaddress` accepts, so treating it as 10 would route a malformed segment
 *  into the dossier's 404 card instead of leaving it on the page that can still
 *  say something about it. */
const OCTET = /^(0|[1-9]\d{0,2})$/;

/**
 * Is this URL segment an IP address — i.e. something the host dossier could be
 * keyed on?
 *
 * Mirrors the server's rule, which normalizes through Python's `ipaddress`
 * (soc_ai/store/host_dossier.normalize_host_key) and 404s anything else. Erring
 * toward "not an address" is the safe direction: a domain wrongly treated as one
 * lands on a 404 card, while an address left on /entity merely misses a richer
 * page.
 */
export function isIpKey(value: string): boolean {
  const key = value.trim();
  if (key === '') return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(key)) {
    return key.split('.').every((octet) => OCTET.test(octet) && Number(octet) <= 255);
  }
  // IPv6: hex groups and colons only, with the ':' that no hostname may carry
  // doing the real work of telling the two apart.
  return key.indexOf(':') !== -1 && /^[0-9a-f:]+$/i.test(key);
}

/**
 * Is this address in private/link-local/loopback space?
 *
 * An APPROXIMATION of the server's `_is_internal_ip`, which tests membership of
 * the operator's CONFIGURED internal CIDRs — a list the SPA does not have. RFC1918
 * is what those CIDRs are in every default deployment, and the failure direction
 * is deliberate: an operator who declares a public CIDR internal gets an address
 * that is treated as external here, which costs a redirect to a page that still
 * works, while the reverse would send an analyst to a dossier that structurally
 * cannot exist.
 */
export function isPrivateIp(ip: string): boolean {
  const key = ip.trim();
  return (
    /^10\./.test(key) ||
    /^192\.168\./.test(key) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(key) ||
    /^169\.254\./.test(key) ||
    /^127\./.test(key) ||
    /^(fc|fd|fe80)/i.test(key) ||
    key === '::1'
  );
}
