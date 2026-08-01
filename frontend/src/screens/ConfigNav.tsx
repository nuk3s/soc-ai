// ---------------------------------------------------------------------------
// ConfigNav — sticky two-level in-page nav for the config page: bold top-level
// section headers (Models & Reasoning, Triage & Workflow, …) with their
// sub-sections indented beneath. Snaps instantly to each sub-section anchor
// (honoring `scroll-mt-*` on the targets — smooth-scroll was slow/choppy on
// this long page) and highlights the active sub-section + its parent. Styled
// to match the app Sidebar nav items. Pure anchors: the click handler is
// progressive enhancement — the `href="#id"` jump still works if JS is
// unavailable. `onNavigate` fires BEFORE the scroll so the page can expand a
// collapsed target and pin the active highlight to the clicked id (the
// scroll-spy is suppressed briefly so it can't misattribute the jump).
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

/**
 * Expand a collapsed target (via onNavigate), then instant-snap to its anchor.
 * Instant snap ('auto', not 'smooth') — smooth-scrolling this long page is
 * slow/choppy; the freshly-shown body changes layout, so scroll next frame.
 * Shared by the sidebar nav (ConfigNav) and the sub-lg "Jump to section" select.
 */
function goToSection(id: string, onNavigate?: (id: string) => void) {
  onNavigate?.(id);
  requestAnimationFrame(() => {
    const el = document.getElementById(id);
    if (!el) return;
    // The sub-lg sticky "Jump to section" bar (ConfigNavSelect) sits at top-0 and
    // overlaps a top-aligned heading, hiding it. Reserve its height as
    // scroll-margin so the landed heading clears it. The bar is display:none at
    // lg+, so its measured height is 0 on desktop — the anchors' own scroll-mt-6
    // is left untouched there (container-agnostic: scrollIntoView honors
    // scroll-margin whatever the scroll parent is, unlike a window-based offset).
    const bar = document.getElementById('config-jump-bar');
    const offset = bar ? Math.ceil(bar.getBoundingClientRect().height) : 0;
    if (offset > 0) el.style.scrollMarginTop = `${offset}px`;
    el.scrollIntoView({ behavior: 'auto', block: 'start' });
  });
  history.replaceState(null, '', `#${id}`);
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
