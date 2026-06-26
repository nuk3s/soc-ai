/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // surfaces & text (dark, cool-neutral)
        bg: '#080a0e',
        'surface-1': '#0b0e13',
        'surface-2': '#0c1016',
        'surface-3': '#11161e',
        'surface-hover': '#0e131a',
        'surface-card': '#0e1117', // login card / dropdowns / palette
        border: '#161c25',
        'border-2': '#1c232e',
        'border-strong': '#2a3645',
        'border-faint': '#11151c',
        'border-input': '#232b37',
        text: '#e6e9ef',
        'text-2': '#cdd5e0',
        dim: '#8b94a3',
        faint: '#5b6473',
        ghost: '#3a424f',

        // accent & status
        accent: '#4b8bf5',
        'accent-deep': '#2c5fd0',
        success: '#3fb950',
        'success-btn': '#1d6b3f',
        'success-btn-border': '#2a8a52',
        warn: '#f5a623',
        danger: '#f04438',

        // verdict
        'verdict-tp': '#f04438',
        'verdict-fp': '#7ba893',
        'verdict-nmi': '#f5a623',
        'verdict-untriaged': '#6b7484',

        // severity
        'sev-critical': '#f04438',
        'sev-high': '#f79009',
        'sev-medium': '#eab308',
        'sev-low': '#6b87a8',

        // detection kind
        'kind-suricata': '#4b8bf5',
        'kind-sigma': '#a472f0',
        'kind-notice': '#2dd4bf',

        // misc mono accents from prototype
        'mono-amber': '#e0a83a',
        'mono-green': '#7ba893',
        'node-host': '#4b8bf5',
        'node-c2': '#e0a83a',
        'node-dc': '#7ba893',
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      fontSize: {
        // semantic sizes used across the spec
        'screen-title': ['20px', { lineHeight: '1.2', letterSpacing: '-0.015em', fontWeight: '600' }],
        headline: ['21px', { lineHeight: '1.32', letterSpacing: '-0.015em', fontWeight: '600' }],
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
