import type { ScenarioResult } from '../api'
import { lazy, Suspense } from 'react'

const NoiseEveChart = lazy(() => import('./Charts').then((module) => ({ default: module.NoiseEveChart })))

export interface NoiseEveCondition {
  id: string
  label: string
  description: string
  result: ScenarioResult
}

interface Props {
  data: NoiseEveCondition[]
  loading: boolean
  seed: number | null
  keyLength: number | null
  onRun: () => void
}

interface ChartPoint {
  label: string
  qber: number
  threshold: number
  description: string
}

function channelLabel(result: ScenarioResult): string {
  const kind = result.channel_class ?? (result.is_authentic ? 'secure' : 'under_attack')
  if (kind === 'degraded') return 'degraded'
  if (kind === 'under_attack') return 'under attack'
  return 'secure'
}

export function NoiseVsEvePanel({ data, loading, seed, keyLength, onRun }: Props) {
  const maxValue = Math.max(0.3, ...data.flatMap(({ result }) => [result.qber, result.dynamic_threshold]))
  const chartMax = Math.min(1, Math.max(0.4, Math.ceil((maxValue + 0.07) * 10) / 10))
  const chartData: ChartPoint[] = data.map(({ label, description, result }) => ({
    label,
    description,
    qber: result.qber,
    threshold: result.dynamic_threshold,
  }))

  return (
    <section id="noise-study" className="panel noise-study section-anchor">
      <div className="panel-title-row">
        <div className="panel-title">Noise or Eve? A controlled comparison</div>
        <button className="btn btn-primary btn-sm" onClick={onRun} disabled={loading}>
          {loading ? 'Measuring four channels…' : 'Run 2 × 2 experiment'}
        </button>
      </div>
      <p className="panel-hint">
        A small factorial experiment changes one cause at a time, then combines them: clean baseline,
        8% software-modelled environmental bit flips, 70% intercept-resend, and both together.
        Every bar is measured by the simulator; the line is that run’s dynamic threshold.
      </p>

      {loading && <div className="noise-study-progress" role="status">Running four controlled channel conditions…</div>}

      {data.length > 0 ? (
        <>
          <div className="noise-study-meta" aria-label="Experiment metadata">
            <span>QKD seed {seed ?? '—'}</span>
            <span>{keyLength?.toLocaleString() ?? '—'} qubits per condition</span>
            <span>base threshold 15%</span>
            <span>CHSH samples use independent randomness</span>
          </div>
          <div className="chart-wrap noise-chart">
            <Suspense fallback={<div className="empty-state chart-loading" role="status">Loading comparison chart…</div>}>
              <NoiseEveChart data={chartData} chartMax={chartMax} />
            </Suspense>
          </div>
          <div className="noise-results" aria-label="Measured comparison results">
          {data.map(({ id, label, description, result }) => (
            <article className="noise-result" key={id}>
                <div className="noise-result-heading">
                  <div>
                    <h3>{label}</h3>
                    <p>{description}</p>
                  </div>
                  <span className={`chip ${result.channel_class === 'under_attack' ? 'chip-red' : result.channel_class === 'degraded' ? 'chip-amber' : 'chip-green'}`}>
                    {channelLabel(result)}
                  </span>
                </div>
                <div className="noise-result-stats">
                  <span><b>{(result.qber * 100).toFixed(2)}%</b> measured QBER</span>
                  <span><b>{(result.dynamic_threshold * 100).toFixed(2)}%</b> dynamic threshold</span>
                  <span><b>{(result.statistical_bounds?.interval.k ?? Math.round(result.qber * result.matching_bases_count)).toLocaleString()} / {result.matching_bases_count.toLocaleString()}</b> mismatches / sifted</span>
                </div>
              </article>
            ))}
          </div>
          <p className="noise-study-note">
            Interpretation: the controlled causes are known because this is a simulator, while the
            QBER and classifications above are measured outputs. Environmental flips and an
            intercept-resend strategy can both raise QBER; the four cases let you compare their
            signatures under the same detector. This models neither a physical fibre nor quantum hardware.
          </p>
        </>
      ) : (
        <div className="empty-state">
          {loading ? 'Collecting the four measured conditions…' : 'Run the comparison to put environmental disturbance and an active eavesdropper side by side.'}
        </div>
      )}
    </section>
  )
}
