// Every host, address, user and domain an investigation, a lead or a hunt
// names is a link (dogfood 2026-10-06, S1). A machine opens its page; any
// other value opens the entity page, which resolves an address a machine
// holds and keeps the rest.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { EntityLink, EntityRefLink } from './EntityLink';

const hrefOf = (node: Parameters<typeof render>[0]) => {
  render(<MemoryRouter>{node}</MemoryRouter>);
  return screen.getByTestId('entity-link').getAttribute('href');
};

describe('EntityLink', () => {
  it('opens the machine page in one step when the machine is known', () => {
    expect(hrefOf(<EntityLink value="192.0.2.10" hostKey="agent:a1" />)).toBe('/hosts/agent%3Aa1');
    expect(screen.getByTestId('entity-link').getAttribute('title')).toBe(
      'Open the machine page for 192.0.2.10.',
    );
  });

  it('sends an address with no known machine to the entity page, never to the list', () => {
    expect(hrefOf(<EntityLink value="192.0.2.226" />)).toBe('/entity/192.0.2.226');
    expect(screen.getByTestId('entity-link').dataset.entityType).toBe('address');
  });

  it('sends a host name to the entity page, which resolves it', () => {
    expect(hrefOf(<EntityLink value="dc01" />)).toBe('/entity/dc01');
    expect(screen.getByTestId('entity-link').dataset.entityType).toBe('host');
  });

  it('carries the type of a user and a domain', () => {
    expect(hrefOf(<EntityLink value="svc-backup" type="user" />)).toBe('/entity/svc-backup?type=user');
  });

  it('carries the type of a domain', () => {
    expect(hrefOf(<EntityLink value="corp.example" type="domain" />)).toBe(
      '/entity/corp.example?type=domain',
    );
  });

  it('sends an external address to the entity page', () => {
    expect(hrefOf(<EntityLink value="8.8.4.4" type="external_address" />)).toBe('/entity/8.8.4.4');
    expect(screen.getByTestId('entity-link').getAttribute('title')).toMatch(
      /^Open the page for the external address 8\.8\.4\.4\./,
    );
  });

  it('never opens a machine for a user, even with a machine key', () => {
    // NEGATIVE CONTROL: an account that shares a name with a machine.
    expect(hrefOf(<EntityLink value="backup" type="user" hostKey="agent:a9" />)).toBe(
      '/entity/backup?type=user',
    );
  });

  it('renders nothing for a blank value', () => {
    render(
      <MemoryRouter>
        <EntityLink value="  " />
      </MemoryRouter>,
    );
    expect(screen.queryByTestId('entity-link')).toBeNull();
  });

  it('links an API reference the way the server resolved it', () => {
    const href = hrefOf(
      <EntityRefLink
        entity={{
          value: '192.0.2.10',
          type: 'address',
          role: 'source',
          host_key: 'agent:a1',
          href: '/hosts/agent%3Aa1',
        }}
      />,
    );
    expect(href).toBe('/hosts/agent%3Aa1');
  });
});
