// Full-width host-activity timeline. Recreated as React SVG from the
// prototype's buildTimeline(): 4 lanes (beacon/interactive/lateral/discrete)
// over a shared 14:00–14:45 axis. Coordinate math preserved verbatim.

const MONO = 'JetBrains Mono, monospace';

const LANES = [
  { y: 42, c: '#e0a83a', label: 'C2 beacon' },
  { y: 92, c: '#a472f0', label: 'Interactive' },
  { y: 142, c: '#f04438', label: 'Lateral / SMB' },
  { y: 192, c: '#4b8bf5', label: 'Discrete' },
];

export function HostActivityTimeline() {
  const x0 = 158;
  const x1 = 980;
  const W = 1000;
  const H = 250;
  const xf = (t: number) => x0 + (t / 45) * (x1 - x0);

  const els: React.ReactNode[] = [];
  const lbls = ['14:00', '14:15', '14:30', '14:45'];

  // gridlines + axis labels
  [0, 15, 30, 45].forEach((t, i) => {
    els.push(<line key={'g' + i} x1={xf(t)} y1={24} x2={xf(t)} y2={208} stroke="#11151c" strokeWidth={1} />);
    els.push(
      <text key={'gl' + i} x={xf(t)} y={226} fill="#5b6473" fontSize={10} fontFamily={MONO} textAnchor={i === 0 ? 'start' : i === 3 ? 'end' : 'middle'}>
        {lbls[i]}
      </text>
    );
  });

  // lane baselines + labels
  LANES.forEach((ln, i) => {
    els.push(<line key={'lb' + i} x1={x0} y1={ln.y} x2={x1} y2={ln.y} stroke="#161c25" strokeWidth={1} />);
    els.push(
      <text key={'ll' + i} x={14} y={ln.y + 3.5} fill={ln.c} fontSize={10.5} fontFamily={MONO} opacity={0.9}>
        {ln.label}
      </text>
    );
  });

  // beacon ticks (regular cadence)
  for (let t = 5; t <= 30; t++) {
    els.push(<line key={'bt' + t} x1={xf(t)} y1={36} x2={xf(t)} y2={48} stroke="#e0a83a" strokeWidth={1.7} opacity={0.82} />);
  }
  els.push(
    <text key="bc" x={xf(17.5)} y={64} fill="#e0a83a" fontSize={8.5} fontFamily={MONO} textAnchor="middle" opacity={0.7}>
      ~60s cadence — machine-regular
    </text>
  );

  // interactive burst
  const bx = xf(30);
  const bw = xf(36) - xf(30);
  els.push(<rect key="ib" x={bx} y={79} width={bw} height={26} rx={4} fill="rgba(164,114,240,.13)" stroke="rgba(164,114,240,.5)" strokeWidth={1} />);
  for (let i = 0; i < 18; i++) {
    const tt = 30 + (i / 17) * 6 + Math.sin(i * 3.3) * 0.12;
    const h = 5 + Math.abs(Math.sin(i * 1.9)) * 9;
    els.push(<line key={'ibt' + i} x1={xf(tt)} y1={92 - h} x2={xf(tt)} y2={92 + h * 0.5} stroke="rgba(164,114,240,.9)" strokeWidth={1} />);
  }
  els.push(
    <text key="ibc" x={bx + bw / 2} y={116} fill="#a472f0" fontSize={8.5} fontFamily={MONO} textAnchor="middle" opacity={0.7}>
      hands-on-keyboard — bursty, no cadence
    </text>
  );

  // lateral sequence
  const lt = [36, 37.6, 39, 41];
  els.push(
    <polyline key="lp" points={lt.map((t) => `${xf(t)},142`).join(' ')} fill="none" stroke="#f04438" strokeWidth={1.4} opacity={0.5} strokeDasharray="3 3" />
  );
  lt.forEach((t, i) => {
    els.push(<circle key={'ld' + i} cx={xf(t)} cy={142} r={4} fill="#0b0e13" stroke="#f04438" strokeWidth={1.8} />);
  });
  els.push(
    <text key="lc" x={xf(38.5)} y={130} fill="#f04438" fontSize={8.5} fontFamily={MONO} textAnchor="middle" opacity={0.85}>
      SMB ×3 → DCSync (192.0.2.5)
    </text>
  );

  // discrete one-off events
  const ev: Array<[number, string, string, number]> = [
    [4, 'exploit', '#f04438', -1],
    [6, 'download', '#e0a83a', 1],
    [29, 'logon', '#4b8bf5', -1],
    [41, 'exfil', '#f04438', 1],
  ];
  ev.forEach((e, i) => {
    const x = xf(e[0]);
    els.push(<rect key={'dv' + i} x={x - 4.5} y={187.5} width={9} height={9} fill="#0b0e13" stroke={e[2]} strokeWidth={1.7} transform={`rotate(45 ${x} 192)`} />);
    els.push(<rect key={'df' + i} x={x - 2} y={190} width={4} height={4} fill={e[2]} transform={`rotate(45 ${x} 192)`} />);
    els.push(
      <text key={'dl' + i} x={x} y={e[3] < 0 ? 180 : 210} fill="#8b94a3" fontSize={8.5} fontFamily={MONO} textAnchor="middle">
        {e[1]}
      </text>
    );
  });

  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ height: 'auto', display: 'block' }} preserveAspectRatio="xMidYMid meet">
      {els}
    </svg>
  );
}
