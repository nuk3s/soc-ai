// The host page's opening statement: what this machine IS, in one sentence.
//
// Every visitor arrives with the same question — "what is this box, and what
// does that mean for the alert I came from?" — and the old page made them
// derive the answer from twelve cards in schema order. The hero now composes
// it: the name a human uses, the identity sentence assembled from every
// resolved fact (lib/hostDossier owns the rules), a coverage chip, and one
// line of relative freshness. Everything here is SWEEP-sourced, so the banner
// keeps answering while Security Onion is unreachable; the live half of the
// page is fetched separately and degrades on its own.

import { Server } from 'lucide-react';
import { cn } from '../lib/cn';
import { provenanceChip, roleAccent, roleRail } from '../lib/hostColors';
import {
  fieldLabel,
  identitySentence,
  isResolved,
  machineRoleView,
  nameSourceTitle,
  relativeAge,
  roleLabel,
  selfReportedFields,
} from '../lib/hostDossier';
import { absTime } from '../lib/timeRange';
import type { Dossier, MachineDetail, MachineNameSource } from '../lib/types';

export interface HostHeroProps {
  dossier: Dossier;
  /** The machine the page is about. Absent on the record page of one
   *  address, which keeps the address hero. */
  machine?: MachineDetail | null;
  /** True when /me answered with a role that cannot write. Said once, here,
   *  because the declare controls are simply absent below and a reader has to
   *  be told why by something. */
  adminBlocked: boolean;
  /** The newest activity the live read saw, when it answered. "last seen 8d
   *  ago" beside 55,665 connections in 24 h read the sweep's stamp as the
   *  host's. The newer of the two wins. */
  lastActivity?: string | null;
}

/** The newer of two ISO stamps, either of which may be absent. */
function newer(a: string | null | undefined, b: string | null | undefined): string | null {
  if (!a) return b ?? null;
  if (!b) return a;
  return new Date(a).getTime() >= new Date(b).getTime() ? a : b;
}

const NAME_SOURCE_PHRASES: Record<MachineNameSource, string> = {
  declared: 'name declared by an operator',
  agent: 'name from the agent',
  dhcp: 'name from a DHCP lease',
  dns: 'name from DNS',
  ntlm: 'name from an NTLM logon',
  other: 'name from other evidence',
};

/**
 * The machine header: the name and where it came from, the agent, the primary
 * address and the role. The identity sentence and the freshness line follow
 * the address hero, so the two pages read alike.
 */
function MachineHero({
  machine,
  dossier,
  adminBlocked,
  lastActivity,
}: {
  machine: MachineDetail;
  dossier: Dossier;
  adminBlocked: boolean;
  lastActivity?: string | null;
}) {
  const lastSeen = newer(machine.last_seen, lastActivity);
  const role = machineRoleView(machine.role);
  const sentence = identitySentence(dossier, machine.name);
  const source = machine.name_source ? NAME_SOURCE_PHRASES[machine.name_source] : null;
  const others = Math.max(0, machine.addresses.length - 1);
  return (
    <section
      data-testid="host-hero"
      className="mb-3 flex overflow-hidden rounded-panel-lg border border-border bg-surface-2"
    >
      <div className={cn('w-1.5 flex-none', roleRail(role.accent))} aria-hidden="true" />
      <div className="min-w-0 flex-1 px-5 py-4">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <span className="flex-none text-dim">
            <Server size={20} />
          </span>
          <span
            data-testid="hero-name"
            className={cn(
              'min-w-0 break-all font-semibold text-white',
              machine.name ? 'text-[21px] tracking-[-0.015em]' : 'font-mono text-[19px]',
            )}
          >
            {machine.name ?? machine.primary_ip}
          </span>
          {machine.name ? (
            source && (
              <span
                data-testid="hero-name-source"
                title={nameSourceTitle(machine.name_source)}
                className="text-[11.5px] text-faint"
              >
                {source}
              </span>
            )
          ) : (
            <span data-testid="hero-name-source" className="text-[11.5px] text-faint">
              no name
            </span>
          )}

          <div className="flex-1" />

          <div className="flex flex-wrap items-center gap-2">
            {role.state === 'declared' || role.state === 'inferred' ? (
              <span
                data-testid="hero-role"
                title={role.title}
                className={cn(
                  'inline-flex flex-none items-center gap-1.5 rounded-pill border px-2.5 py-[3px] font-mono text-[11.5px] font-semibold',
                  roleAccent(role.accent),
                )}
              >
                {role.text}
                <span className="font-sans text-[10px] font-normal opacity-80">{role.note}</span>
              </span>
            ) : role.state === 'unknown' ? (
              <span
                data-testid="hero-role"
                title={role.title}
                className="inline-flex flex-none items-center rounded-pill border border-border-input bg-surface-3 px-2.5 py-[3px] font-mono text-[11.5px] font-semibold text-dim"
              >
                role unknown
              </span>
            ) : (
              <span
                data-testid="hero-role"
                title={role.title}
                className="inline-flex flex-none items-center rounded-pill border border-warn/40 bg-warn/[0.08] px-2.5 py-[3px] font-mono text-[11.5px] font-semibold text-warn"
              >
                {role.text}
              </span>
            )}
          </div>
        </div>

        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[12.5px]">
          <span data-testid="hero-primary" title="The primary address. This page reads its activity, its observations and its facts.">
            <span className="text-faint">primary address </span>
            <span className="font-mono text-text-2">{machine.primary_ip}</span>
            {others > 0 && (
              <a href="#addresses" className="ml-1.5 text-[11.5px] text-accent hover:underline">
                and {others} more
              </a>
            )}
          </span>
          {machine.agent ? (
            <span
              data-testid="hero-agent"
              className={cn(
                'inline-flex items-center gap-1.5 rounded-pill border px-2.5 py-[2px] font-mono text-[11.5px]',
                provenanceChip('hostlog'),
              )}
              title="An agent on this machine ships its own logs. This page can say more than network traffic alone shows."
            >
              agent {machine.agent.name}
              {machine.agent.os && <span className="font-sans opacity-80">· {machine.agent.os}</span>}
              <span className="font-sans opacity-80" title={absTime(machine.agent.last_report)}>
                · last report {relativeAge(machine.agent.last_report)}
              </span>
            </span>
          ) : (
            <span
              data-testid="hero-agent"
              title="No agent logs reach the grid from this machine. Everything here comes from network traffic."
              className="inline-flex items-center rounded-pill border border-border-input bg-surface-3 px-2.5 py-[2px] text-[11.5px] text-dim"
            >
              No agent reports from this machine
            </span>
          )}
        </div>

        <p data-testid="host-sentence" className="mt-2.5 max-w-[860px] text-[14px] leading-[1.65] text-text-2">
          {sentence.map((part, i) =>
            part.strong ? (
              <strong key={i} className="font-semibold text-text">
                {part.text}
              </strong>
            ) : (
              <span key={i}>{part.text}</span>
            ),
          )}
        </p>

        <div data-testid="hero-facts" className="mt-2.5 flex flex-wrap gap-x-5 gap-y-1 font-mono text-[11px] text-faint">
          <span title="Events on every address of this machine">{machine.events.toLocaleString()} events</span>
          <span title={absTime(machine.first_seen)}>first seen {relativeAge(machine.first_seen)}</span>
          <span data-testid="hero-last-seen" title={absTime(lastSeen)}>
            last seen {relativeAge(lastSeen)}
          </span>
          {dossier.last_built_at ? (
            <span title={absTime(dossier.last_built_at)}>swept {relativeAge(dossier.last_built_at)}</span>
          ) : (
            <span title="No completed sweep has written the primary address yet">
              {dossier.build_error ? 'never successfully swept' : 'not swept yet'}
            </span>
          )}
        </div>

        {adminBlocked && (
          <div className="mt-2 text-[11.5px] text-faint">
            This page is read-only. Sign in as an admin to declare values or resolve disagreements.
          </div>
        )}
      </div>
    </section>
  );
}

export function HostHero({ dossier, machine, adminBlocked, lastActivity }: HostHeroProps) {
  if (machine) {
    return (
      <MachineHero
        machine={machine}
        dossier={dossier}
        adminBlocked={adminBlocked}
        lastActivity={lastActivity}
      />
    );
  }
  return <AddressHero dossier={dossier} adminBlocked={adminBlocked} lastActivity={lastActivity} />;
}

function AddressHero({ dossier, adminBlocked, lastActivity }: HostHeroProps) {
  const lastSeen = newer(dossier.last_seen, lastActivity);
  const hostnameField = dossier.fields.find((f) => f.field === 'hostname');
  const roleField = dossier.fields.find((f) => f.field === 'role');
  const hostname =
    hostnameField && isResolved(hostnameField) ? (hostnameField.value ?? '').trim() || null : null;
  const role = roleField && isResolved(roleField) ? (roleField.value ?? '').trim() || null : null;
  const selfReported = selfReportedFields(dossier.fields);
  const sentence = identitySentence(dossier);

  return (
    <section
      data-testid="host-hero"
      className="mb-3 flex overflow-hidden rounded-panel-lg border border-border bg-surface-2"
    >
      {/* The role accent, and the largest piece of colour on the page. A host
          page should be recognisable as "the hypervisor one" from the shape of
          the screen before a word of it is read. */}
      <div className={cn('w-1.5 flex-none', roleRail(role))} aria-hidden="true" />

      <div className="min-w-0 flex-1 px-5 py-4">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <span className="flex-none text-dim">
            <Server size={20} />
          </span>
          {/* The name a human uses leads; the address it is keyed on never
              leaves, because that is what every other surface links on. */}
          <span
            data-testid="hero-name"
            className={cn(
              'min-w-0 break-all font-semibold text-white',
              hostname ? 'text-[21px] tracking-[-0.015em]' : 'font-mono text-[19px]',
            )}
          >
            {hostname ?? dossier.ip}
          </span>
          {hostname && (
            <span className="font-mono text-[13px] text-dim" title="The address this profile is keyed on">
              {dossier.ip}
            </span>
          )}

          <div className="flex-1" />

          <div className="flex flex-wrap items-center gap-2">
            {role && (
              <span
                data-testid="hero-role"
                title="What type of machine this is"
                className={cn(
                  'inline-flex flex-none items-center rounded-pill border px-2.5 py-[3px] font-mono text-[11.5px] font-semibold',
                  roleAccent(role),
                )}
              >
                {roleLabel(role)}
              </span>
            )}
            {/* The page's most load-bearing caveat, as a glance mark. The
                briefing strip below says the negative in full words; this only
                has to be readable from across the room. `reporting` comes off
                the wire, not from the fields: an override masks the winning
                source, and the staleness gate is a server knob — a field that
                once came from the agent proves the agent EXISTED, not that it
                still reports. The negative stays the weaker claim on purpose:
                the agent lane also goes quiet when the grid ships no host-log
                datasets at all, so absence of agent DATA is provable and
                absence of an agent is not. */}
            {dossier.reporting ? (
              <span
                data-testid="hero-agent"
                title={
                  selfReported.length > 0
                    ? `This machine reports on itself. ${selfReported
                        .map((name) => fieldLabel(name))
                        .join(', ')} came from logs it ships. This page can say more than network traffic alone shows.`
                    : 'An agent on this machine ships its own logs. This page can say more than network traffic alone shows.'
                }
                className={cn(
                  'inline-flex flex-none items-center rounded-pill border px-2.5 py-[3px] font-mono text-[11.5px] font-semibold',
                  provenanceChip('hostlog'),
                )}
              >
                agent on box
              </span>
            ) : (
              <span
                data-testid="hero-agent"
                title="No agent logs reach the grid from this address. Everything here comes from the network traffic of this host."
                className="inline-flex flex-none items-center rounded-pill border border-border-input bg-surface-3 px-2.5 py-[3px] font-mono text-[11.5px] font-semibold text-dim"
              >
                network-only view
              </span>
            )}
          </div>
        </div>

        {/* The composed answer. Bold nouns, plain connective tissue. */}
        <p data-testid="host-sentence" className="mt-2.5 max-w-[860px] text-[14px] leading-[1.65] text-text-2">
          {sentence.map((part, i) =>
            part.strong ? (
              <strong key={i} className="font-semibold text-text">
                {part.text}
              </strong>
            ) : (
              <span key={i}>{part.text}</span>
            ),
          )}
        </p>

        {/* Freshness a reader can feel. Four second-precision timestamps was
            the old header; the wall clock now rides in the hover. `swept` only
            claims a build that actually completed (F3's "built from 433
            events" beside "last built —"). */}
        <div data-testid="hero-facts" className="mt-2.5 flex flex-wrap gap-x-5 gap-y-1 font-mono text-[11px] text-faint">
          <span title="Events the sweep has aggregated for this host">
            {dossier.event_count.toLocaleString()} events
          </span>
          <span title={absTime(dossier.first_seen)}>first seen {relativeAge(dossier.first_seen)}</span>
          <span data-testid="hero-last-seen" title={absTime(lastSeen)}>
            last seen {relativeAge(lastSeen)}
          </span>
          {dossier.last_built_at ? (
            <span title={absTime(dossier.last_built_at)}>
              swept {relativeAge(dossier.last_built_at)}
            </span>
          ) : (
            <span title="No completed sweep has written this host yet">
              {dossier.build_error ? 'never successfully swept' : 'not swept yet'}
            </span>
          )}
        </div>

        {adminBlocked && (
          <div className="mt-2 text-[11.5px] text-faint">
            This page is read-only. Sign in as an admin to declare values or resolve disagreements.
          </div>
        )}
      </div>
    </section>
  );
}
