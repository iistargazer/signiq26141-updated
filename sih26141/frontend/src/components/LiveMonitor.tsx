import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, ReferenceLine } from 'recharts'
import type { LiveScenario } from '../App'

interface Props {
  live: Record<string, LiveScenario>
  log: string[]
  running: boolean
  /** Base threshold from the slider — drives the dashed reference line. */
  baseThreshold: number
}

const SERIES: Record<string, { color: string; label: string }> = {
  secure: { color: '#34d399', label: 'Secure channel' },
  attack: { color: '#f87171', label: 'Attack (full intercept)' },
  custom: { color: '#fbbf24', label: 'Custom ratio' },
}

export function LiveMonitor({ live, log, running, baseThreshold }: Props) {
  const names = Object.keys(live)
  if (names.length === 0) return null

  const chartData: { processed: number; [k: string]: number | undefined }[] = []
  const keys = names.filter((n) => live[n].points.length > 0)
  const maxLen = Math.max(0, ...keys.map((n) => live[n].points.length))
  for (let i = 0; i < maxLen; i++) {
    const row: { processed: number; [k: string]: number | undefined } = { processed: i }
    for (const n of keys) {
      const p = live[n].points[i]
      if (p) {
        row[`${n}_qber`] = p.qber
        row[`${n}_thr`] = p.threshold
        row.processed = p.processed
      }
    }
    chartData.push(row)
  }

  return (
    <section className="panel">
      <div className="panel-title-row">
        <div className="panel-title">Live Channel Monitor</div>
        {running && <span className="pulse-dot" aria-label="streaming" />}
      </div>
      <div className="monitor-grid">
        {keys.map((n) => {
          const s = live[n]
          const pct = s.total > 0 ? Math.round((s.processed / s.total) * 100) : 0
          const meta = SERIES[n] ?? { color: '#60a5fa', label: n }
          return (
            <div key={n} className="monitor-stats">
              <div className="stat-line">
                <span className="stat-name" style={{ color: meta.color }}>
                  {meta.label}
                </span>
                <span className={`chip ${s.qber > s.threshold ? 'chip-red' : 'chip-green'}`}>
                  {s.qber > s.threshold ? 'QBER above threshold' : 'channel stable'}
                </span>
              </div>
              <div className="stat-grid">
                <div>
                  <div className="stat-num">{pct}%</div>
                  <div className="stat-label">transmitted</div>
                </div>
                <div>
                  <div className="stat-num">{s.sifted.toLocaleString()}</div>
                  <div className="stat-label">sifted bits</div>
                </div>
                <div>
                  <div className="stat-num">{s.mismatches.toLocaleString()}</div>
                  <div className="stat-label">mismatches</div>
                </div>
                <div>
                  <div className="stat-num">{(s.qber * 100).toFixed(2)}%</div>
                  <div className="stat-label">live QBER</div>
                </div>
              </div>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: `${pct}%`, background: meta.color }} />
              </div>
            </div>
          )
        })}
      </div>
      <div className="chart-wrap">
        <ResponsiveContainer width="100%" height={260}>
          <LineChart data={chartData} margin={{ top: 10, right: 20, bottom: 0, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1f2a44" />
            <XAxis dataKey="processed" stroke="#64748b" tick={{ fontSize: 11 }} />
            <YAxis stroke="#64748b" tick={{ fontSize: 11 }} tickFormatter={(v: number) => `${(v * 100).toFixed(0)}%`} />
            <Tooltip
              contentStyle={{ background: '#0d1526', border: '1px solid #1f2a44', borderRadius: 8, fontSize: 12 }}
              formatter={(v) => `${((v as number) * 100).toFixed(3)}%`}
              labelFormatter={(l) => `qubit #${l}`}
            />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            {keys.map((n) => {
              const meta = SERIES[n] ?? { color: '#60a5fa', label: n }
              return (
                <Line
                  key={n}
                  type="monotone"
                  dataKey={`${n}_qber`}
                  name={`${meta.label} — QBER`}
                  stroke={meta.color}
                  dot={false}
                  strokeWidth={2}
                  isAnimationActive={false}
                />
              )
            })}
            {keys.map((n) => {
              const meta = SERIES[n] ?? { color: '#60a5fa', label: n }
              return (
                <Line
                  key={`${n}-thr`}
                  type="monotone"
                  dataKey={`${n}_thr`}
                  name={`${meta.label} — threshold`}
                  stroke={meta.color}
                  strokeDasharray="6 4"
                  strokeWidth={1}
                  dot={false}
                  isAnimationActive={false}
                  legendType="none"
                />
              )
            })}
            <ReferenceLine
              y={baseThreshold}
              stroke="#475569"
              strokeDasharray="2 2"
              label={{ value: `base ${(baseThreshold * 100).toFixed(0)}%`, fill: '#475569', fontSize: 10, position: 'insideTopRight' }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
      {log.length > 0 && (
        <div className="event-log">
          <div className="event-log-title">Event log</div>
          {log.map((line, i) => (
            <div key={i} className="event-line">
              {line}
            </div>
          ))}
        </div>
      )}
    </section>
  )
}
