// The chosen "Scope" mark + mono `soc_ai` wordmark, recreated as inline SVG.
// A radar/onion ring with one flagged amber signal node on the outer ring.

interface MarkProps {
  size?: number;
  glow?: boolean;
}

export function ScopeMark({ size = 28, glow = false }: MarkProps) {
  const g = Math.round(size * 0.62);
  return (
    <div
      className="flex flex-none items-center justify-center"
      style={{
        width: size,
        height: size,
        borderRadius: Math.round(size * 0.26),
        background: 'linear-gradient(140deg,#4b8bf5,#2c5fd0)',
        boxShadow:
          'inset 0 0 0 1px rgba(255,255,255,.14), 0 0 0 1px rgba(75,139,245,.4)' +
          (glow ? ', 0 8px 24px rgba(75,139,245,.28)' : ''),
      }}
      aria-hidden
    >
      <svg width={g} height={g} viewBox="0 0 32 32" fill="none">
        <circle cx={16} cy={16} r={11} stroke="rgba(255,255,255,.95)" strokeWidth={2.6} />
        <circle cx={16} cy={16} r={5} stroke="rgba(255,255,255,.55)" strokeWidth={2} />
        <circle cx={16} cy={16} r={1.7} fill="#fff" />
        <circle cx={24} cy={8.4} r={4.6} fill="#0b1f44" />
        <circle cx={24} cy={8.4} r={3.1} fill="#f5a623" />
      </svg>
    </div>
  );
}

interface WordmarkProps {
  size?: number;
  className?: string;
}

export function Wordmark({ size = 14.5, className = '' }: WordmarkProps) {
  return (
    <div
      className={`font-mono font-semibold whitespace-nowrap ${className}`}
      style={{ fontSize: size, letterSpacing: '-0.01em' }}
    >
      soc<span className="text-accent">_</span>ai
    </div>
  );
}
