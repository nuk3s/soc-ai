// ---------------------------------------------------------------------------
// ConfigNav — sticky in-page section nav for the config page. Smooth-scrolls
// to each section anchor (honoring `scroll-mt-*` on the targets) and highlights
// the active section. Styled to match the app Sidebar nav items. Pure anchors:
// the click handler is progressive enhancement — the `href="#id"` jump still
// works if JS/IntersectionObserver are unavailable.
// ---------------------------------------------------------------------------

interface ConfigNavSection {
  id: string;
  label: string;
}

interface ConfigNavProps {
  sections: ConfigNavSection[];
  activeId: string;
}

export function ConfigNav({ sections, activeId }: ConfigNavProps) {
  return (
    <nav className="sticky top-5 flex flex-col gap-0.5">
      <div className="px-2 pb-1.5 text-[10.5px] font-semibold uppercase tracking-[.07em] text-faint">
        Config
      </div>
      {sections.map((s) => {
        const active = s.id === activeId;
        return (
          <a
            key={s.id}
            href={`#${s.id}`}
            onClick={(e) => {
              e.preventDefault();
              document.getElementById(s.id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
              history.replaceState(null, '', `#${s.id}`);
            }}
            className="rounded-control px-[9px] py-[6px] text-[12.5px] font-medium hover:bg-surface-3"
            style={{
              background: active ? '#11161e' : 'transparent',
              color: active ? '#e6e9ef' : '#8b94a3',
            }}
          >
            {s.label}
          </a>
        );
      })}
    </nav>
  );
}
