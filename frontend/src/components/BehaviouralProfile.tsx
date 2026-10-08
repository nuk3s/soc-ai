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

/** One line under the header that says what each status word means. Four
 *  words sat on the rows with no definition, and "blind" read as an alarm
 *  (dogfood 2026-10-06). */
export const PROFILE_LEGEND =
  'measured: a real baseline, and a departure from it counts. ' +
  'learning: under 7 days of history, so nothing scores yet. ' +
  'blind: no log source on the grid can measure this row for this host. It marks a gap in coverage and raises no alarm. ' +
  'stale: the evidence is older than the staleness window.';

/**
 * A connection rate whose three numbers are nearly the same, as one number.
 * "work 124 · off 124 · weekend 122" told the analyst nothing to act on
 * (dogfood 2026-10-06). Within 10 percent of each other, the row reads
 * "about 124 per hour at all times" and the tooltip keeps the three.
 * Null when the numbers differ, or the summary has another shape.
 */
export function collapsedRate(summary: string): string | null {
  const pick = (word: string) => {
    const m = summary.match(new RegExp(`\\b${word} (\\d+(?:\\.\\d+)?)\\b`));
    return m ? Number(m[1]) : null;
  };
  const values = [pick('work'), pick('off'), pick('weekend')];
  if (values.some((v) => v == null)) return null;
  const nums = values as number[];
  const hi = Math.max(...nums);
  const lo = Math.min(...nums);
  if (hi <= 0 || (hi - lo) / hi > 0.1) return null;
  const typical = Math.round(nums.reduce((a, b) => a + b, 0) / nums.length);
  return `about ${typical.toLocaleString()} per hour at all times`;
}

const PREVIEW = 8;
const MORE = /\s\+\d+ more$/;

// What a row with no members says. Three different absences, three sentences.
function fallbackFor(d: ProfileDimension): string {
  // The reason travels with the row. A bare "cannot be measured" beside an
  // "agent on box" chip could not say whether the agent or the join was missing.
  if (d.coverage === 'blind') {
    return d.coverage_reason
      ? `cannot be measured: ${d.coverage_reason}`
      : 'cannot be measured for this host';
  }
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
  const rate = d.dimension === 'connection_rate' ? collapsedRate(d.summary) : null;
  if (rate) {
    return (
      <span
        data-testid="profile-rate-collapsed"
        className="min-w-0 flex-1 break-words text-text-2"
        title={d.summary}
      >
        {rate}
      </span>
    );
  }
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

/** Why a host has no profile, from the setting the dossier read carries. */
export function noProfileText(profilesEnabled: boolean | null | undefined): string {
  if (profilesEnabled === true) {
    // The panel said "Turn profiles on in Config" while profiles were on
    // (dogfood 2026-10-06). The cause on a deployment that runs them is the
    // host's own history.
    return 'This host has too few events for a profile. The profile sweep builds one from up to 30 days of history. soc-ai scores nothing here until then.';
  }
  if (profilesEnabled === false) {
    return 'No profile exists for this host. Profiles are off. Turn them on in Config › Behavioural profiles. soc-ai scores nothing here until then.';
  }
  return 'No profile exists for this host yet. The host has too few events, or profiles are off in Config › Behavioural profiles. soc-ai scores nothing here until then.';
}

export function BehaviouralProfile({
  profile,
  profilesEnabled,
}: {
  profile: ProfileDimension[];
  /** Whether the profile sweep runs on this deployment. Null or absent when
   *  the server does not say. */
  profilesEnabled?: boolean | null;
}) {
  if (profile.length === 0) {
    // Absence is a fact the page must state. A missing panel is
    // indistinguishable from "this host has no unusual behaviour".
    return (
      <Panel className="mt-4">
        <PanelHeader icon={<Activity size={16} />} title="Behavioural profile" />
        <div data-testid="profile-empty" className="px-[15px] py-3 text-[13px] text-dim">
          {noProfileText(profilesEnabled)}
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
      <div data-testid="profile-legend" className="border-b border-border px-[15px] py-2 text-[11px] leading-[1.5] text-faint">
        {PROFILE_LEGEND}
      </div>
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
