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

export function ConfigNav({ groups, activeId, onNavigate }: ConfigNavProps) {
  const go = (id: string) => {
    // Expand a collapsed target first, then scroll (the freshly-shown body
    // changes layout, so scroll on the next frame). Instant snap ('auto', not
    // 'smooth') — smooth-scrolling this long page is slow/choppy.
    onNavigate?.(id);
    requestAnimationFrame(() => {
      document.getElementById(id)?.scrollIntoView({ behavior: 'auto', block: 'start' });
    });
    history.replaceState(null, '', `#${id}`);
  };

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
