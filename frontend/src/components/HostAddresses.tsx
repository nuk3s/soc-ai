// Every address of one machine, and the containers it runs.
//
// The host list used to show one row per address, so a machine with a bridge
// and a VPN leg was three rows that each told a third of the story (dogfood
// 2026-10-02, U3). The machine page now owns the addresses. Each row says how
// soc-ai tied the address to the machine, when it was first and last seen,
// and how many events it carries. Expand a row for the facts the sweep holds
// about that one address.

import { ChevronDown, ChevronRight, Network } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { getDossier } from '../lib/api';
import { cn } from '../lib/cn';
import {
  addressKindLabel,
  addressKindTitle,
  fieldLabel,
  partitionFields,
  provenancePhrase,
  valueText,
} from '../lib/hostDossier';
import { plural } from '../lib/plural';
import { absTime, ago } from '../lib/timeRange';
import type { MachineAddress, MachineContainer, MachineDetail } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { Panel, PanelHeader } from './Panel';
import { Spinner } from './States';

/** The facts the sweep holds about one address, read-only. A declaration on
 *  this address is made on its own record page. */
function AddressFacts({
  ip,
  primary,
  focusField,
}: {
  ip: string;
  primary: boolean;
  focusField: string | null;
}) {
  const read = useAsync(() => getDossier(ip), [ip]);
  const d = read.data;
  const recordHref = `/hosts/${encodeURIComponent(ip)}?view=address`;
  return (
    <div data-testid={`address-facts-${ip}`} className="px-[15px] pb-3 pt-1">
      {read.loading && !d ? (
        <div className="flex items-center gap-2 text-[12px] text-dim">
          <Spinner size={12} /> Reading the facts for this address…
        </div>
      ) : read.error && !d ? (
        <div className="flex flex-wrap items-center gap-2 text-[12px] text-danger">
          The facts for this address could not be read. {read.error.message}
          <button
            type="button"
            onClick={read.refetch}
            className="rounded-control border border-danger/40 px-2 py-0.5 text-[11px] font-semibold hover:bg-danger/10"
          >
            Retry
          </button>
        </div>
      ) : !d ? null : !d.found ? (
        <div className="text-[12px] text-faint">The sweep holds no record for this address.</div>
      ) : (
        <>
          {partitionFields(d.fields).known.length === 0 ? (
            <div className="text-[12px] text-faint">The sweep has confirmed no fact for this address yet.</div>
          ) : (
            <dl className="grid grid-cols-[140px_1fr] gap-x-3 gap-y-1 text-[12px]">
              {partitionFields(d.fields).known.map((f) => {
                const phrase = provenancePhrase(f);
                return (
                  <div
                    key={f.field}
                    data-field={f.field}
                    data-highlight={focusField === f.field ? 'true' : 'false'}
                    className={cn(
                      'contents',
                      focusField === f.field && '[&>*]:bg-accent/[0.06]',
                    )}
                  >
                    <dt className="text-[10.5px] font-semibold uppercase tracking-[.05em] text-faint">
                      {fieldLabel(f.field)}
                    </dt>
                    <dd className="min-w-0 text-text-2">
                      <span className="font-mono">{valueText(f.field, f.value, f.value_json) ?? ''}</span>
                      {phrase && <span className="ml-2 text-[11px] text-faint">{phrase}</span>}
                    </dd>
                  </div>
                );
              })}
            </dl>
          )}
          {d.conflict_count > 0 && (
            <div className="mt-2 text-[12px] font-semibold text-warn">
              {plural(d.conflict_count, 'disagreement')} on this address. Open the record to decide.
            </div>
          )}
          {!primary && (
            <div className="mt-2 text-[11.5px] text-faint">
              The facts panels below describe the primary address.{' '}
              <Link to={recordHref} className="font-semibold text-accent hover:underline">
                Open the record for {ip}
              </Link>{' '}
              to declare a value on this address.
            </div>
          )}
        </>
      )}
    </div>
  );
}

function AddressRow({
  a,
  open,
  focused,
  onToggle,
  focusField,
}: {
  a: MachineAddress;
  open: boolean;
  focused: boolean;
  onToggle: () => void;
  focusField: string | null;
}) {
  return (
    <>
      <tr
        id={`address-${a.ip}`}
        data-testid={`address-row-${a.ip}`}
        data-focus={focused ? 'true' : 'false'}
        className={cn(
          'border-b border-border-faint',
          focused && 'border-l-2 border-l-accent bg-accent/[0.05]',
        )}
      >
        <td className="px-[15px] py-2">
          <span className="inline-flex items-center gap-1.5">
            <span className="font-mono text-[12.5px] text-text">{a.ip}</span>
            {a.primary && (
              <span
                title="The primary address. The page reads its activity, observations and facts."
                className="rounded-chip border border-accent/40 px-1 font-mono text-[9.5px] font-semibold text-accent"
              >
                primary
              </span>
            )}
          </span>
        </td>
        <td className="px-2.5 py-2 text-[12px] text-text-2" title={addressKindTitle(a.kind)}>
          {addressKindLabel(a.kind)}
        </td>
        <td className="px-2.5 py-2 text-right font-mono text-[11.5px] text-faint" title={absTime(a.first_seen)}>
          {ago(a.first_seen)}
        </td>
        <td className="px-2.5 py-2 text-right font-mono text-[11.5px] text-faint" title={absTime(a.last_seen)}>
          {ago(a.last_seen)}
        </td>
        <td className="px-2.5 py-2 text-right font-mono text-[12px] text-dim">{a.events.toLocaleString()}</td>
        <td className="px-[15px] py-2 text-right">
          <button
            type="button"
            onClick={onToggle}
            aria-expanded={open}
            aria-label={`${open ? 'Hide' : 'Show'} the facts for ${a.ip}`}
            className="inline-flex items-center gap-1 rounded-control border border-border-strong px-2 py-0.5 text-[11px] font-semibold text-dim hover:text-text"
          >
            {open ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
            Facts
          </button>
        </td>
      </tr>
      {open && (
        <tr className="border-b border-border-faint bg-surface-2/50">
          <td colSpan={6}>
            <AddressFacts ip={a.ip} primary={a.primary} focusField={focused ? focusField : null} />
          </td>
        </tr>
      )}
    </>
  );
}

function ContainerRow({ c }: { c: MachineContainer }) {
  return (
    <tr className="border-b border-border-faint last:border-0">
      <td className="px-[15px] py-1.5 font-mono text-[12px] text-text-2">{c.ip}</td>
      <td className="px-2.5 py-1.5 text-right font-mono text-[11.5px] text-faint" title={absTime(c.first_seen)}>
        {ago(c.first_seen)}
      </td>
      <td className="px-2.5 py-1.5 text-right font-mono text-[11.5px] text-faint" title={absTime(c.last_seen)}>
        {ago(c.last_seen)}
      </td>
      <td className="px-[15px] py-1.5 text-right font-mono text-[12px] text-dim">{c.events.toLocaleString()}</td>
    </tr>
  );
}

export interface HostAddressesProps {
  machine: MachineDetail;
  /** The address the URL names (`?address=`). It opens expanded and in view. */
  focusAddress: string | null;
  /** The field the URL names (`?field=`), highlighted in the focused facts. */
  focusField: string | null;
}

export function HostAddresses({ machine, focusAddress, focusField }: HostAddressesProps) {
  // Primary first, then the newest.
  const addresses = [...machine.addresses].sort(
    (a, b) =>
      Number(b.primary) - Number(a.primary) || (b.last_seen ?? '').localeCompare(a.last_seen ?? ''),
  );
  const focusIsAddress = !!focusAddress && addresses.some((a) => a.ip === focusAddress);
  const [open, setOpen] = useState<Set<string>>(
    () => new Set(focusIsAddress && focusAddress ? [focusAddress] : []),
  );
  const toggle = (ip: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });

  // Bring the focused address into view once per link.
  const scrolledFor = useRef<string | null>(null);
  useEffect(() => {
    if (!focusIsAddress || !focusAddress || scrolledFor.current === focusAddress) return;
    scrolledFor.current = focusAddress;
    setOpen((prev) => (prev.has(focusAddress) ? prev : new Set(prev).add(focusAddress)));
    const el = document.getElementById(`address-${focusAddress}`);
    (el as HTMLElement | null)?.scrollIntoView?.({ behavior: 'auto', block: 'center' });
  }, [focusAddress, focusIsAddress]);

  const containers = machine.containers ?? [];
  return (
    <section id="addresses" data-testid="host-addresses" className="mb-3">
      <Panel>
        <PanelHeader
          icon={<Network size={15} />}
          title="Addresses"
          right={
            <span className="font-mono text-[11px] text-faint">
              {plural(addresses.length, 'address', 'addresses')}
            </span>
          }
        />
        {focusAddress && !focusIsAddress && (
          <div className="border-b border-border-faint px-[15px] py-2 text-[12px] text-dim">
            The link named {focusAddress}. This machine does not hold that address now.
          </div>
        )}
        <table className="w-full text-[12.5px]">
          <thead className="border-b border-border bg-surface-2 text-[10.5px] uppercase tracking-[.06em] text-faint">
            <tr>
              <th scope="col" className="px-[15px] py-2 text-left font-semibold">
                Address
              </th>
              <th scope="col" className="px-2.5 py-2 text-left font-semibold">
                Type
              </th>
              <th scope="col" className="px-2.5 py-2 text-right font-semibold">
                First seen
              </th>
              <th scope="col" className="px-2.5 py-2 text-right font-semibold">
                Last seen
              </th>
              <th scope="col" className="px-2.5 py-2 text-right font-semibold">
                Events
              </th>
              <th scope="col" className="px-[15px] py-2 text-right font-semibold">
                <span className="sr-only">Facts</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {addresses.map((a) => (
              <AddressRow
                key={a.ip}
                a={a}
                open={open.has(a.ip)}
                focused={a.ip === focusAddress}
                onToggle={() => toggle(a.ip)}
                focusField={focusField}
              />
            ))}
          </tbody>
        </table>
        {containers.length > 0 && (
          <details data-testid="host-containers" className="border-t border-border">
            <summary className="cursor-pointer px-[15px] py-2.5 text-[12.5px] font-semibold text-text-2 hover:text-text">
              {plural(containers.length, 'container')} on this machine
            </summary>
            <div className="px-[15px] pb-1 text-[11.5px] text-faint">
              A container address sits inside a bridge network that this machine owns. Only the
              endpoint sensor of this machine sees it.
            </div>
            <table className="w-full text-[12.5px]">
              <thead className="border-b border-border-faint text-[10.5px] uppercase tracking-[.06em] text-faint">
                <tr>
                  <th scope="col" className="px-[15px] py-1.5 text-left font-semibold">
                    Address
                  </th>
                  <th scope="col" className="px-2.5 py-1.5 text-right font-semibold">
                    First seen
                  </th>
                  <th scope="col" className="px-2.5 py-1.5 text-right font-semibold">
                    Last seen
                  </th>
                  <th scope="col" className="px-[15px] py-1.5 text-right font-semibold">
                    Events
                  </th>
                </tr>
              </thead>
              <tbody>
                {containers.map((c) => (
                  <ContainerRow key={c.ip} c={c} />
                ))}
              </tbody>
            </table>
          </details>
        )}
      </Panel>
    </section>
  );
}
