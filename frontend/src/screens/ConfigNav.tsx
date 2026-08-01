// ---------------------------------------------------------------------------
// ConfigNav — the MASTER of the config page's master-detail layout: bold
// top-level section headers (Models & Reasoning, Triage & Workflow, …) with
// their sub-sections indented beneath. Clicking selects a section (the page
// renders only the selected one) and highlights it + its parent. Styled to
// match the app Sidebar nav items. `href="#id"` keeps every entry a real,
// copyable deep-link.
// ---------------------------------------------------------------------------

interface ConfigNavChild {
  id: string;
  label: string;
}

export interface ConfigNavGroup {
  label: string;
  children: ConfigNavChild[];
}

interface ConfigNavProps {
  groups: ConfigNavGroup[];
  activeId: string;
  /** Called before scrolling so the page can expand a collapsed target and pin the highlight. */
  onNavigate?: (id: string) => void;
}

function goToSection(id: string, onNavigate?: (id: string) => void) {
  // Master-detail: a nav click SELECTS the section (the page renders only that
  // one), so there is nothing here to scroll to — Config's onNavigate owns
  // selection, hash sync, and resetting the pane to its top.
  onNavigate?.(id);
}

export function ConfigNav({ groups, activeId, onNavigate }: ConfigNavProps) {
  const go = (id: string) => goToSection(id, onNavigate);

  return (
    <nav className="sticky top-5 flex max-h-[calc(100vh-40px)] flex-col gap-0.5 overflow-y-auto pr-1">
      <div className="px-2 pb-1.5 text-[10.5px] font-semibold uppercase tracking-[.07em] text-faint">
        Config
      </div>
      {groups.map((g) => {
        const parentActive = g.children.some((c) => c.id === activeId);
        const first = g.children[0];
        return (
          <div key={g.label} className="flex flex-col gap-0.5">
            {/* Top-level header — clicking jumps to its first sub-section. */}
            <a
              href={first ? `#${first.id}` : undefined}
              onClick={(e) => {
                e.preventDefault();
                if (first) go(first.id);
              }}
              className="mt-2.5 rounded-control px-[9px] py-[4px] text-[11px] font-bold uppercase tracking-[.06em] first:mt-0 hover:bg-surface-3"
              style={{ color: parentActive ? '#c8cfda' : '#6b7484' }}
            >
              {g.label}
            </a>
            {g.children.map((s) => {
              const active = s.id === activeId;
              return (
                <a
                  key={s.id}
                  href={`#${s.id}`}
                  onClick={(e) => {
                    e.preventDefault();
                    go(s.id);
                  }}
                  className="rounded-control py-[5px] pl-[18px] pr-[9px] text-[12.5px] font-medium hover:bg-surface-3"
                  style={{
                    background: active ? '#11161e' : 'transparent',
                    color: active ? '#e6e9ef' : '#8b94a3',
                  }}
                >
                  {s.label}
                </a>
              );
            })}
          </div>
        );
      })}
    </nav>
  );
}

/**
 * Sub-lg (< 1024px) replacement for the sidebar ConfigNav, which is
 * `hidden ... lg:block` and so vanishes on narrow viewports with no substitute.
 * A sticky "Jump to section" <select> mirroring the same grouped section list
 * (parents as <optgroup>, sub-sections as <option>); picking one expands the
 * target and instant-snaps to it via the shared goToSection mechanism. Shown
 * only below lg (`block lg:hidden`) so it never doubles the sidebar.
 */
export function ConfigNavSelect({ groups, activeId, onNavigate }: ConfigNavProps) {
  // Reflect the scroll-spy's active section, but only when it's actually one of
  // our options — otherwise fall back to the disabled placeholder.
  const selected = groups.some((g) => g.children.some((c) => c.id === activeId))
    ? activeId
    : '';
  return (
    <label
      id="config-jump-bar"
      className="sticky top-0 z-10 mb-4 flex items-center gap-2 bg-bg/95 py-2 text-[11px] font-semibold uppercase tracking-[.06em] text-faint backdrop-blur lg:hidden"
    >
      Jump to section
      <select
        value={selected}
        onChange={(e) => {
          if (e.target.value) goToSection(e.target.value, onNavigate);
        }}
        className="min-w-0 flex-1 rounded-control border border-border-input bg-bg px-2.5 py-1.5 text-[12.5px] font-normal normal-case tracking-normal text-text outline-none focus:border-accent"
      >
        <option value="" disabled>
          Choose a section…
        </option>
        {groups.map((g) => (
          <optgroup key={g.label} label={g.label}>
            {g.children.map((c) => (
              <option key={c.id} value={c.id}>
                {c.label}
              </option>
            ))}
          </optgroup>
        ))}
      </select>
    </label>
  );
}
