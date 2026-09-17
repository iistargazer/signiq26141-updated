import type { ScenarioResult } from '../api'
import type { LiveScenario } from '../App'

interface Props {
  title: string
  progress?: LiveScenario
  result?: ScenarioResult
  streaming?: boolean
}

/** Chip + label for the three-way channel classification. */
function ClassChip({ result }: { result: ScenarioResult }) {
  const cls = result.channel_class ?? (result.is_authentic ? 'secure' : 'under_attack')
  if (cls === 'secure')
    return <span className="chip chip-green">✓ secure</span>
  if (cls === 'degraded')
    return <span className="chip chip-amber">degradation warning</span>
  return <span className="chip chip-red">✗ under attack</span>
}

export function StatusCard({ title, progress, result, streaming }: Props) {
  const authentic = result?.is_authentic
  const degraded = result?.channel_class === 'degraded'
  const stateClass = result ? (degraded ? 'card-amber' : authentic ? 'card-green' : 'card-red') : streaming ? 'card-live' : ''
  const qber = result ? result.qber : progress?.qber ?? null
  const threshold = result ? result.dynamic_threshold : progress?.threshold ?? null

  return (
    <div className={`status-card ${stateClass}`}>
      <div className="card-head">
        <h3>{title}</h3>
        {result ? (
          <ClassChip result={result} />
        ) : (
          <span className="chip chip-gray">{streaming ? 'streaming…' : 'idle'}</span>
        )}
      </div>

      {progress && !result && (
        <div className="card-progress">
          <div className="bar-track">
            <div
              className="bar-fill"
              style={{
                width: `${progress.total > 0 ? Math.round((progress.processed / progress.total) * 100) : 0}%`,
              }}
            />
          </div>
          <div className="card-progress-text">
            qubit {progress.processed.toLocaleString()} / {progress.total.toLocaleString()} ·{' '}
            {progress.sifted.toLocaleString()} sifted
          </div>
        </div>
      )}

      <div className="card-metrics">
        <div className="metric">
          <div className="metric-value">{qber === null ? '—' : `${(qber * 100).toFixed(2)}%`}</div>
          <div className="metric-label">Measured QBER</div>
        </div>
        <div className="metric">
          <div className="metric-value">{threshold === null ? '—' : `${(threshold * 100).toFixed(2)}%`}</div>
          <div className="metric-label">Dynamic threshold</div>
        </div>
        <div className="metric">
          <div className="metric-value">{result ? result.sifted_key_length.toLocaleString() : '—'}</div>
          <div className="metric-label">Sifted key bits</div>
        </div>
      </div>

      {(result?.relay_hops ?? 0) > 0 && result?.relay_stats && (
        <div className="card-relay">
          <div className="card-relay-label">
            {result.relay_hops} relay hop{(result.relay_hops ?? 0) > 1 ? 's' : ''} · key survival{' '}
            {result.raw_key_length > 0
              ? `${((result.sifted_key_length / result.raw_key_length) * 100).toFixed(1)}%`
              : '—'}
          </div>
          <div className="card-relay-strip">
            {result.relay_stats.map((h) => (
              <span
                key={h.hop}
                className={`hop-dot ${h.interceptions > 0 ? 'hop-dot-bad' : ''}`}
                title={`${h.from}→${h.to}: ${h.out_qubits}/${h.in_qubits} sifted, ${h.interceptions} interceptions`}
              />
            ))}
            <span className="card-relay-nodes">
              {result.relay_stats.map((h) => h.from).concat('Bob').join(' → ')}
            </span>
          </div>
        </div>
      )}

      {result && !authentic && (
        <div className="card-alert">
          {result.channel_class === 'under_attack'
            ? 'Eavesdropping signature — QBER exceeds the finite-key bound. Key distillation aborted.'
            : 'QBER above tolerance — no shared secret distilled.'}
        </div>
      )}
      {result && degraded && (
        <div className="card-alert card-alert-amber">
          Channel Degradation Warning — QBER above the noise floor but below the attack line
          {result.noise_rate ? ` (fiber noise ${(result.noise_rate * 100).toFixed(1)}%)` : ''}. Environmental, not
          adversarial — keys distilled with caution.
        </div>
      )}
    </div>
  )
}
