// SVG donut confidence ring. Circumference for r=16 is 2πr ≈ 100.53; the spec
// computes the visible arc as offset = len * (1 - conf).

interface ConfidenceRingProps {
  conf: number;
  color: string;
  size?: number;
}

export function ConfidenceRing({ conf, color, size = 46 }: ConfidenceRingProps) {
  const len = 100.53;
  const off = (len * (1 - conf)).toFixed(1);
  return (
    <svg width={size} height={size} viewBox="0 0 36 36" style={{ transform: 'rotate(-90deg)' }} aria-hidden>
      <circle cx={18} cy={18} r={16} fill="none" stroke="#1c232e" strokeWidth={3} />
      <circle
        cx={18}
        cy={18}
        r={16}
        fill="none"
        stroke={color}
        strokeWidth={3}
        strokeLinecap="round"
        strokeDasharray={len}
        strokeDashoffset={off}
      />
    </svg>
  );
}

/** Small risk-score donut (Hunt detail host-risk panel). */
export function RiskRing({ score, color, size = 58 }: { score: number; color: string; size?: number }) {
  const len = 100.5;
  const off = (len * (1 - score / 100)).toFixed(1);
  return (
    <div className="relative flex-none" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox="0 0 36 36" style={{ transform: 'rotate(-90deg)' }} aria-hidden>
        <circle cx={18} cy={18} r={16} fill="none" stroke="#1c232e" strokeWidth={3.5} />
        <circle
          cx={18}
          cy={18}
          r={16}
          fill="none"
          stroke={color}
          strokeWidth={3.5}
          strokeLinecap="round"
          strokeDasharray={len}
          strokeDashoffset={off}
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="font-mono text-[16px] font-bold" style={{ color }}>
          {score}
        </span>
      </div>
    </div>
  );
}
