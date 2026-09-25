import { Activity } from 'lucide-react';
import { useState } from 'react';

import type { ProfileDimension } from '../lib/types';
import { Panel, PanelHeader } from './Panel';

// ---------------------------------------------------------------------------
// What is normal for this host — the baseline the hunting layer scores
// departures against, one row per dimension.
//
// The coverage chip on the right is the load-bearing part. `measured` over an
// empty set means the host genuinely does none of this and a new member is a
// real departure; `blind` means no plane on the grid can answer for it;
// `learning` means under seven days of history. Rendered identically, those
// are the most dangerous three words in the app, and the panel exists so they
// are never rendered identically.
//
// The support days sit next to the chip because "measured" over a 4-sample
// median will be believed. The number is what lets a reader decide not to.
// ---------------------------------------------------------------------------

const LABEL: Record<string, string> = {
  served_ports: 'served ports',
  consumed_ports: 'consumed ports',
  peers_out: 'peers out',
  dns_names: 'DNS names',
  process_names: 'processes',
  process_parents: 'process pairs',
  logon_users: 'logon users',
  active_hours: 'active hours',
  connection_rate: 'connection rate',
};

const COVERAGE: Record<string, { label: string; color: string; title: string }> = {
  measured: {
    label: 'measured',
    color: '#3fb950',
    title: 'A real baseline. A member that is absent from it is a real departure. An empty baseline means this host does none of this.',
  },
  learning: {
    label: 'learning',
    color: '#d29922',
    title: 'This row has under 7 days of history. soc-ai scores nothing against it yet.',
  },
  blind: {
    label: 'blind',
    color: '#d29922',
    title: 'No plane on this grid can answer this dimension for this host. soc-ai can score no departure here.',
  },
  behind_proxy: {
    label: 'behind proxy',
    color: '#8b949e',
    title: 'The external destinations of this host all resolve to a proxy. The proxy carries this dimension.',
  },
  unmeasurable: {
    label: 'unmeasurable',
    color: '#f85149',
    title: 'The grid refused the query that measures this dimension. soc-ai can score no departure here. The row shows the reason the grid gave.',
  },
};

function CoverageChip({ coverage, days }: { coverage: string; days: number }) {
  const c = COVERAGE[coverage] ?? { label: coverage, color: '#8b949e', title: '' };
  return (
    <span
      className="inline-flex flex-none items-center gap-1.5 whitespace-nowrap rounded-chip border px-1.5 py-px font-mono text-[10px] font-semibold"
      style={{ color: c.color, borderColor: `${c.color}59`, background: `${c.color}17` }}
      title={c.title}
      data-testid={`profile-coverage-${coverage}`}
    >
      {c.label}
      {days > 0 && <span className="font-normal opacity-80" title={`This row has ${days} days of history.`}>· {days}d of history</span>}
    </span>
  );
}

const PREVIEW = 8;
const MORE = /\s\+\d+ more$/;

// What a row with no members says. Three different absences, three sentences.
function fallbackFor(d: ProfileDimension): string {
  if (d.coverage === 'blind') return 'cannot be measured for this host';
  if (d.coverage === 'unmeasurable') {
    return `not measured: ${d.coverage_reason ?? 'the grid refused the query'}`;
  }
  return 'nothing observed';
}

// A set row says "197 peers · a, b, c, +189 more". The 189 exist and the
// backend sends them, so "+189 more" opens rather than naming what the page
// cannot show. Shaped rows (hours, rates) have no members and print as-is.
function ProfileSummary({ d }: { d: ProfileDimension }) {
  const [open, setOpen] = useState(false);
  const members = d.shape === 'categorical' ? d.top : [];
  const fallback = fallbackFor(d);
  if (members.length <= PREVIEW) {
    return (
      <span className="min-w-0 flex-1 break-words text-text-2" title={d.summary}>
        {d.summary || fallback}
      </span>
    );
  }
  const head = d.summary.replace(MORE, '');
  const rest = members.length - PREVIEW;
  return (
    <span className="min-w-0 flex-1 break-words text-text-2">
      {open ? (
        <>
          {head.split(' · ')[0]} ·{' '}
          {members.map(([name, count], i) => (
            <span key={name} title={`seen ${count.toLocaleString()} time${count === 1 ? '' : 's'}`}>
              {i > 0 && ', '}
              {name}
            </span>
          ))}{' '}
          <button type="button" onClick={() => setOpen(false)} className="text-accent hover:underline">
            show fewer
          </button>
        </>
      ) : (
        <>
          {head}{' '}
          <button
            type="button"
            onClick={() => setOpen(true)}
            className="text-accent hover:underline"
            title={`Show all ${members.length.toLocaleString()}`}
          >
            +{rest} more
          </button>
        </>
      )}
    </span>
  );
}

export function BehaviouralProfile({ profile }: { profile: ProfileDimension[] }) {
  if (profile.length === 0) {
    // Absence is a fact the page must state. A missing panel is
    // indistinguishable from "this host has no unusual behaviour".
    return (
      <Panel className="mt-4">
        <PanelHeader icon={<Activity size={16} />} title="Behavioural profile" />
        <div className="px-[15px] py-3 text-[13px] text-dim">
          No profile exists for this host yet. The dossier sweep builds one from up to 30 days of history.
          Turn profiles on in Config › Behavioural profiles. soc-ai scores nothing here until then.
        </div>
      </Panel>
    );
  }
  const window = profile[0]?.window_days ?? 30;
  return (
    <Panel className="mt-4">
      <PanelHeader
        icon={<Activity size={16} />}
        title="Behavioural profile"
        right={
          <span className="text-[11px] text-dim" title={`The sweep builds the profile from up to ${window} days of history. The chip on each row shows the days available for that dimension.`}>
            what is normal here · built from up to {window} days of history
          </span>
        }
      />
      <ul className="divide-y divide-border" data-testid="behavioural-profile">
        {profile.map((d) => (
          <li key={d.dimension} className="flex items-start gap-3 px-[15px] py-2.5 text-[13px]">
            <span className="w-[120px] flex-none pt-px text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
              {LABEL[d.dimension] ?? d.dimension}
            </span>
            <ProfileSummary d={d} />
            <CoverageChip coverage={d.coverage} days={d.support_days} />
          </li>
        ))}
      </ul>
    </Panel>
  );
}
