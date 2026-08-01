/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // surfaces & text (dark, cool-neutral)
        bg: 'rgb(var(--bg) / <alpha-value>)',
        'surface-1': 'rgb(var(--surface-1) / <alpha-value>)',
        'surface-2': 'rgb(var(--surface-2) / <alpha-value>)',
        'surface-3': 'rgb(var(--surface-3) / <alpha-value>)',
        'surface-hover': 'rgb(var(--surface-hover) / <alpha-value>)',
        'surface-card': 'rgb(var(--surface-card) / <alpha-value>)',
        border: 'rgb(var(--border) / <alpha-value>)',
        'border-2': 'rgb(var(--border-2) / <alpha-value>)',
        'border-strong': 'rgb(var(--border-strong) / <alpha-value>)',
        'border-faint': 'rgb(var(--border-faint) / <alpha-value>)',
        'border-input': 'rgb(var(--border-input) / <alpha-value>)',
        text: 'rgb(var(--text) / <alpha-value>)',
        'text-2': 'rgb(var(--text-2) / <alpha-value>)',
        dim: 'rgb(var(--dim) / <alpha-value>)',
        faint: 'rgb(var(--faint) / <alpha-value>)',
        ghost: 'rgb(var(--ghost) / <alpha-value>)',
        // accent & status
        accent: 'rgb(var(--accent) / <alpha-value>)',
        'accent-deep': 'rgb(var(--accent-deep) / <alpha-value>)',
        focus: 'rgb(var(--focus) / <alpha-value>)',
        success: 'rgb(var(--success) / <alpha-value>)',
        'success-btn': 'rgb(var(--success-btn) / <alpha-value>)',
        'success-btn-border': 'rgb(var(--success-btn-border) / <alpha-value>)',
        warn: 'rgb(var(--warn) / <alpha-value>)',
        danger: 'rgb(var(--danger) / <alpha-value>)',
        // verdict
        'verdict-tp': 'rgb(var(--verdict-tp) / <alpha-value>)',
        'verdict-fp': 'rgb(var(--verdict-fp) / <alpha-value>)',
        'verdict-nmi': 'rgb(var(--verdict-nmi) / <alpha-value>)',
        'verdict-untriaged': 'rgb(var(--verdict-untriaged) / <alpha-value>)',
        // severity — ONE canonical ramp (green is never a severity)
        'sev-critical': 'rgb(var(--sev-critical) / <alpha-value>)',
        'sev-high': 'rgb(var(--sev-high) / <alpha-value>)',
        'sev-medium': 'rgb(var(--sev-medium) / <alpha-value>)',
        'sev-low': 'rgb(var(--sev-low) / <alpha-value>)',
        'sev-info': 'rgb(var(--sev-info) / <alpha-value>)',
        // detection kind
        'kind-suricata': 'rgb(var(--kind-suricata) / <alpha-value>)',
        'kind-sigma': 'rgb(var(--kind-sigma) / <alpha-value>)',
        'kind-notice': 'rgb(var(--kind-notice) / <alpha-value>)',
        // misc mono accents / graph nodes
        'mono-amber': 'rgb(var(--mono-amber) / <alpha-value>)',
        'mono-green': 'rgb(var(--mono-green) / <alpha-value>)',
        'node-host': 'rgb(var(--node-host) / <alpha-value>)',
        'node-c2': 'rgb(var(--node-c2) / <alpha-value>)',
        'node-dc': 'rgb(var(--node-dc) / <alpha-value>)',
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      fontSize: {
        // Named type roles (hard floor 11px). Adopt incrementally in place of the
        // ad-hoc text-[Npx] values; 11px is only for uppercase-tracked labels and
        // mono captions — anything read rather than glanced at is >=12px.
        micro: ['11px', { lineHeight: '1.3', letterSpacing: '0.06em' }],
        meta: ['12px', { lineHeight: '1.4' }],
        ui: ['13px', { lineHeight: '1.45' }],
        body: ['13px', { lineHeight: '1.55' }],
        section: ['15px', { lineHeight: '1.35', fontWeight: '600' }],
        title: ['20px', { lineHeight: '1.2', letterSpacing: '-0.015em', fontWeight: '600' }],
        headline: ['21px', { lineHeight: '1.32', letterSpacing: '-0.015em', fontWeight: '600' }],
        kpi: ['24px', { lineHeight: '1.1', fontWeight: '600' }],
      },
      borderRadius: {
        chip: '5px',
        badge: '6px',
        control: '8px',
        card: '11px',
        panel: '12px',
        'panel-lg': '14px',
        pill: '20px',
      },
      boxShadow: {
        drawer: '-30px 0 80px rgba(0,0,0,.5)',
        dropdown: '0 20px 54px rgba(0,0,0,.6)',
        palette: '0 30px 80px rgba(0,0,0,.6)',
        'login-card': '0 24px 60px rgba(0,0,0,.5)',
        'logo-glow': 'inset 0 0 0 1px rgba(255,255,255,.14), 0 0 0 1px rgba(75,139,245,.4), 0 8px 24px rgba(75,139,245,.28)',
      },
      transitionTimingFunction: {
        drawer: 'cubic-bezier(.2,.8,.2,1)',
      },
      keyframes: {
        spin: { to: { transform: 'rotate(360deg)' } },
        pulseDot: { '0%,100%': { opacity: '1' }, '50%': { opacity: '.25' } },
        pulseRing: { '0%,100%': { opacity: '.45' }, '50%': { opacity: '.12' } },
        blink: { '0%,100%': { opacity: '.15' }, '50%': { opacity: '1' } },
        slideIn: { from: { transform: 'translateX(24px)', opacity: '0' }, to: { transform: 'translateX(0)', opacity: '1' } },
        fadeUp: { from: { transform: 'translateY(8px)', opacity: '0' }, to: { transform: 'translateY(0)', opacity: '1' } },
        // translateX is relative to the BAR's own width (~35-40%), so the end
        // value must overshoot 100% for the bar to sweep fully across + exit.
        scanline: { '0%': { transform: 'translateX(-120%)' }, '100%': { transform: 'translateX(340%)' } },
        barGrow: { from: { transform: 'scaleX(0)' }, to: { transform: 'scaleX(1)' } },
        dash: { to: { strokeDashoffset: '-24' } },
      },
      animation: {
        spin: 'spin .8s linear infinite',
        pulseDot: 'pulseDot 2s infinite',
        'pulseDot-slow': 'pulseDot 2.4s infinite',
        pulseRing: 'pulseRing 2s infinite',
        blink: 'blink 1s infinite',
        slideIn: 'slideIn .26s cubic-bezier(.2,.8,.2,1) both',
        fadeUp: 'fadeUp .16s ease both',
        'fadeUp-slow': 'fadeUp .2s ease both',
        scanline: 'scanline 1.3s linear infinite',
        'scanline-slow': 'scanline 1.4s linear infinite',
        barGrow: 'barGrow .5s ease both',
        dash: 'dash .6s linear infinite',
      },
      maxWidth: {
        permalink: '860px',
        workstation: '1380px',
      },
    },
  },
  plugins: [],
}
