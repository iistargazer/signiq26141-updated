import { lazy, Suspense } from 'react'

const SweepChart = lazy(() => import('./Charts').then((module) => ({ default: module.SweepChart })))

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
          <Suspense fallback={<div className="empty-state chart-loading" role="status">Loading sweep chart…</div>}>
            <SweepChart data={data} />
          </Suspense>
        </div>
      ) : (
        <div className="empty-state">{loading ? 'Running sweep…' : 'Run the sweep to compare measured QBER with theory.'}</div>
      )}
    </section>
  )
}
