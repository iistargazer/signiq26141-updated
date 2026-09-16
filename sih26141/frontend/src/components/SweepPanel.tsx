import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, ReferenceLine } from 'recharts'

interface SweepPoint {
  ratio: number
  qber: number
  threshold: number
  theory: number
}

interface Props {
  data: SweepPoint[]
  loading: boolean
  onRun: () => void
}

export function SweepPanel({ data, loading, onRun }: Props) {
  return (
    <section className="panel">
      <div className="panel-title-row">
        <div className="panel-title">QBER vs. Eavesdropping Intensity</div>
        <button className="btn btn-ghost" onClick={onRun} disabled={loading}>
          {loading ? 'Sweeping…' : 'Run parameter sweep'}
        </button>
      </div>
      <p className="panel-hint">
        Measured QBER across Eve's intercept ratio (0–100% of qubits), against the theoretical
        prediction QBER ≈ ratio / 3 and the Hoeffding-adjusted detection threshold.
      </p>
      {data.length > 0 ? (
        <div className="chart-wrap">
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={data} margin={{ top: 10, right: 20, bottom: 5, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2a44" />
              <XAxis
                dataKey="ratio"
                stroke="#64748b"
                tick={{ fontSize: 11 }}
                tickFormatter={(v: number) => `${Math.round(v * 100)}%`}
              />
              <YAxis stroke="#64748b" tick={{ fontSize: 11 }} tickFormatter={(v: number) => `${(v * 100).toFixed(0)}%`} />
              <Tooltip
                contentStyle={{ background: '#0d1526', border: '1px solid #1f2a44', borderRadius: 8, fontSize: 12 }}
                formatter={(v) => `${((v as number) * 100).toFixed(2)}%`}
                labelFormatter={(l) => `Eve intercepts ${(Number(l) * 100).toFixed(0)}% of qubits`}
              />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <ReferenceLine y={data[0]?.threshold ?? 0.2} stroke="#f87171" strokeDasharray="6 4" label={{ value: 'detection threshold', fill: '#f87171', fontSize: 10, position: 'insideTopRight' }} />
              <Bar dataKey="qber" name="Measured QBER" fill="#60a5fa" radius={[3, 3, 0, 0]} />
              <Bar dataKey="theory" name="Theoretical (ratio/3)" fill="#334155" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <div className="empty-state">{loading ? 'Running sweep…' : 'Run the sweep to compare measured QBER with theory.'}</div>
      )}
    </section>
  )
}
