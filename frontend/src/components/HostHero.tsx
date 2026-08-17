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
  relativeAge,
  roleLabel,
  selfReportedFields,
} from '../lib/hostDossier';
import { absTime } from '../lib/timeRange';
import type { Dossier } from '../lib/types';

export interface HostHeroProps {
  dossier: Dossier;
  /** True when /me answered with a role that cannot write. Said once, here,
   *  because the declare controls are simply absent below and a reader has to
   *  be told why by something. */
  adminBlocked: boolean;
}

export function HostHero({ dossier, adminBlocked }: HostHeroProps) {
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
                title="What kind of machine this is"
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
                    ? `This machine reports on itself: ${selfReported
                        .map((name) => fieldLabel(name))
                        .join(', ')} came from logs it ships, so this page can say more than the wire alone shows.`
                    : 'An agent on this machine ships its own logs, so this page can say more than the wire alone shows.'
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
                title="Nothing here came from the machine itself — no agent logs reach the grid from this address, so only its network traffic speaks for it."
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
          <span title={absTime(dossier.last_seen)}>last seen {relativeAge(dossier.last_seen)}</span>
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
            Read-only: sign in as an admin to declare values or resolve disagreements.
          </div>
        )}
      </div>
    </section>
  );
}
