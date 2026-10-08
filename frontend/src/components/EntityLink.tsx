import type { MouseEvent, ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { cn } from '../lib/cn';
import { entityHref, guessEntityType } from '../lib/entityPath';
import type { EntityRef, EntityType } from '../lib/types';

// ---------------------------------------------------------------------------
// One host, address, user or domain, as a link to the page that answers for
// it (dogfood 2026-10-06, S1).
//
// Every address and host name on an investigation was plain text, so the
// analyst who read "192.0.2.226" in a verdict had no way to that host. A
// machine opens its page. An address with no machine, a user, a domain and an
// external address open the entity page, which says what the value is and
// what soc-ai holds on it.
// ---------------------------------------------------------------------------

/** The words the tooltip uses for each type. */
const TYPE_WORD: Record<EntityType, string> = {
  address: 'address',
  external_address: 'external address',
  host: 'host',
  user: 'user',
  domain: 'domain',
  name: 'name',
};

export interface EntityLinkProps {
  /** The value as the record names it: an address, a host name, a user
   *  account or a domain. */
  value: string;
  /** What the value is. Omitted, an address reads as an address and any other
   *  value as a host name. Send `user` or `domain` when the record knows it. */
  type?: EntityType | string | null;
  /** The machine that holds the value, from `EntityRef.host_key`. With it the
   *  link opens the machine page in one step. */
  hostKey?: string | null;
  /** The text of the link. Defaults to the value. */
  children?: ReactNode;
  className?: string;
  /** Replaces the default tooltip. */
  title?: string;
  /** For a link inside a clickable row or card: the click opens this page
   *  and does not reach the row. */
  stopPropagation?: boolean;
}

/** The tooltip for one entity link. */
export function entityLinkTitle(value: string, type: EntityType, hostKey?: string | null): string {
  if (hostKey && type !== 'user' && type !== 'domain') {
    return `Open the machine page for ${value}.`;
  }
  return `Open the page for the ${TYPE_WORD[type]} ${value}. The page lists the investigations, leads and observations that name it.`;
}

/** One entity, linked. A blank value renders nothing. */
export function EntityLink({
  value,
  type,
  hostKey,
  children,
  className,
  title,
  stopPropagation = false,
}: EntityLinkProps) {
  const v = (value ?? '').trim();
  if (!v) return null;
  const known = (type && type in TYPE_WORD ? type : guessEntityType(v)) as EntityType;
  const to = entityHref(v, known, hostKey);
  return (
    <Link
      to={to}
      data-testid="entity-link"
      data-entity-type={known}
      title={title ?? entityLinkTitle(v, known, hostKey)}
      onClick={stopPropagation ? (e: MouseEvent) => e.stopPropagation() : undefined}
      className={cn(
        'font-mono text-accent underline decoration-accent/40 underline-offset-2 hover:decoration-accent',
        className,
      )}
    >
      {children ?? v}
    </Link>
  );
}

/** An `EntityRef` from the API, linked. The server already resolved the
 *  machine, so the link opens the right page in one step. */
export function EntityRefLink({
  entity,
  children,
  className,
}: {
  entity: EntityRef;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <EntityLink value={entity.value} type={entity.type} hostKey={entity.host_key} className={className}>
      {children}
    </EntityLink>
  );
}
