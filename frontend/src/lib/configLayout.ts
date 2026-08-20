import type { SettingGroup } from './types';

// ---------------------------------------------------------------------------
// The Config page's information architecture, extracted to a lib so BOTH the
// Config screen and the command palette derive the SAME section ids — a palette
// entry that navigates to /config#<id> must agree with the id the page renders.
// The server-driven settings groups carry their parent in GET /config
// (SECTION_PARENTS in soc_ai/store/config_overrides.py is the source of truth
// for THEIR grouping); the frontend-owned standalone panels declare theirs in
// PANELS below.
// ---------------------------------------------------------------------------

/** Slugify a section title into a stable DOM id / anchor fragment. */
export function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
}

/** Top-level parent headers, in display order. A parent the frontend doesn't
 * know yet is appended after these. */
export const PARENT_ORDER = [
  'Models & Reasoning',
  'Triage & Workflow',
  'Retrieval & Memory',
  'Privacy & Egress',
  'Data & Enrichment',
  'System',
];

/** Standalone (frontend-owned) sections: stable DOM id (deep-link anchor —
 * these ids predate the grouped nav and MUST NOT change), label (doubles as the
 * `collapsed`-map key), parent header, and placement relative to the parent's
 * server-driven groups. */
export interface PanelDef {
  id: string;
  label: string;
  parent: string;
  placement?: { afterGroup?: string; at?: 'start' };
}

export const PANELS: PanelDef[] = [
  { id: 'agent-tools', label: 'Agent tools', parent: 'Models & Reasoning' },
  { id: 'notifications-webhook', label: 'Notification webhook', parent: 'Triage & Workflow', placement: { afterGroup: 'Notifications' } },
  { id: 'runbooks', label: 'Runbooks', parent: 'Retrieval & Memory' },
  { id: 'egress-policy', label: 'Egress policy', parent: 'Privacy & Egress', placement: { at: 'start' } },
  { id: 'internal-identifiers', label: 'Internal identifiers', parent: 'Privacy & Egress', placement: { afterGroup: 'Discovery' } },
  { id: 'redaction-preview', label: 'Redaction preview', parent: 'Privacy & Egress' },
  { id: 'data-sources', label: 'Data sources', parent: 'Data & Enrichment', placement: { at: 'start' } },
  { id: 'detection-tuning', label: 'Detection tuning', parent: 'Data & Enrichment' },
  { id: 'api-keys', label: 'API keys', parent: 'Data & Enrichment', placement: { afterGroup: 'Online enrichment' } },
  { id: 'about', label: 'About', parent: 'System', placement: { at: 'start' } },
  { id: 'users', label: 'Users', parent: 'System' },
  { id: 'api-tokens', label: 'API tokens', parent: 'System' },
  { id: 'maintenance', label: 'Scheduled maintenance', parent: 'System' },
  { id: 'diagnostics', label: 'Diagnostics', parent: 'System' },
  { id: 'danger-zone', label: 'Danger Zone', parent: 'System' },
];

/** Ids the group-id generator must never produce: every standalone panel id
 * plus in-page anchors that aren't nav sections. */
export const RESERVED_IDS: ReadonlySet<string> = new Set([
  ...PANELS.map((p) => p.id),
  'rag-reembed',
]);

/** In-page anchors that live INSIDE a section (not sections themselves), and
 * the label of the section that hosts each. A deep-link to one selects the
 * hosting section, then scrolls to the anchor within it. */
export const SUB_ANCHOR_HOSTS: Record<string, string> = {
  'rag-reembed': 'Retrieval (RAG)',
};

export type ConfigChild =
  | { kind: 'group'; id: string; label: string; group: SettingGroup }
  | { kind: 'panel'; id: string; label: string };

export interface ConfigParent {
  label: string;
  children: ConfigChild[];
}

/**
 * Build the two-level layout: PARENT_ORDER headers, each holding the
 * server-driven settings groups whose `parent` (from GET /config) matches, with
 * the standalone panels spliced in per their PANELS placement. Nav order ==
 * render order by construction.
 *
 * Collision-proof group ids: slugs are deduped against the reserved panel ids
 * AND each other, so a future server section titled e.g. "Users" can never
 * produce a duplicate DOM id. Current titles slug cleanly, so the historical
 * anchors (#agent, #retrieval-rag, …) are unchanged.
 */
export function buildConfigLayout(groups: SettingGroup[] | undefined): ConfigParent[] {
  const used = new Set(RESERVED_IDS);
  const idFor = (title: string) => {
    const base = slug(title) || 'section';
    let id = base;
    for (let n = 2; used.has(id); n++) id = `${base}-${n}`;
    used.add(id);
    return id;
  };
  const parentOrder = [...PARENT_ORDER];
  const byParent = new Map<string, ConfigChild[]>();
  const bucket = (parent: string) => {
    let children = byParent.get(parent);
    if (!children) {
      children = [];
      byParent.set(parent, children);
      if (!parentOrder.includes(parent)) parentOrder.push(parent);
    }
    return children;
  };
  for (const g of groups ?? []) {
    bucket(g.parent ?? g.title).push({ kind: 'group', id: idFor(g.title), label: g.title, group: g });
  }
  for (const p of PANELS) {
    const children = bucket(p.parent);
    const child: ConfigChild = { kind: 'panel', id: p.id, label: p.label };
    const after = p.placement?.afterGroup;
    if (p.placement?.at === 'start') {
      children.unshift(child);
    } else if (after) {
      const i = children.findIndex((c) => c.kind === 'group' && c.label === after);
      children.splice(i === -1 ? children.length : i + 1, 0, child);
    } else {
      children.push(child);
    }
  }
  return parentOrder
    .filter((label) => byParent.has(label))
    .map((label) => ({ label, children: byParent.get(label) ?? [] }));
}

/** Setting key → the id of the section that renders it (for the apply-bar
 * chips and the palette's jump-to-setting). */
export function keyToSectionId(layout: ConfigParent[]): Record<string, string> {
  const map: Record<string, string> = {};
  for (const p of layout) {
    for (const c of p.children) {
      if (c.kind === 'group') {
        for (const item of c.group.items) map[item.key] = c.id;
      }
    }
  }
  return map;
}

/** Setting key → the TITLE of the group that owns it — the same string
 * Config.tsx's per-section Advanced fold keys under (`${title}:advanced` in
 * the `collapsed` record). Distinct from keyToSectionId above, whose values
 * are DOM ids, not display titles (a group's `label` and its owning
 * SettingGroup's `title` are the same string by construction — see
 * buildConfigLayout). */
export function keyToSectionTitle(layout: ConfigParent[]): Record<string, string> {
  const map: Record<string, string> = {};
  for (const p of layout) {
    for (const c of p.children) {
      if (c.kind === 'group') {
        for (const item of c.group.items) map[item.key] = c.label;
      }
    }
  }
  return map;
}

/** Setting key → its day1 tier, indexed the same way as keyToSectionTitle
 * above. A jump that only has the KEY (the palette's router-state
 * highlightKey hand-off) needs this to decide whether unfolding the owning
 * section's Advanced fold is correct: doing it for a day1 target would be
 * wrong (day1 rows render unfolded already) AND would persist the unfold —
 * `collapsed` mirrors to localStorage — silently eroding the day-1 view on
 * every such jump. */
export function keyToDay1(layout: ConfigParent[]): Record<string, boolean> {
  const map: Record<string, boolean> = {};
  for (const p of layout) {
    for (const c of p.children) {
      if (c.kind === 'group') {
        for (const item of c.group.items) map[item.key] = item.day1;
      }
    }
  }
  return map;
}
