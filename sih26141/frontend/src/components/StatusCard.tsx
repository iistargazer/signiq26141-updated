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
          The measured QBER exceeded this run’s configured decision line. No key was distilled;
          the software-model result does not identify the cause.
        </div>
      )}
      {result && authentic && !result.key_distilled && (
        <div className="card-alert card-alert-amber">
          QBER is within the configured decision line, but the modeled entropy budget was
          insufficient to produce a key. No session key was created.
        </div>
      )}
      {result && degraded && (
        <div className="card-alert card-alert-amber">
          Channel Degradation Warning — QBER above the noise floor but below the attack line
          {result.noise_rate ? ` (fiber noise ${(result.noise_rate * 100).toFixed(1)}%)` : ''}. Environmental, not
          adversarial — keys distilled with caution.
        </div>
      )}
      {result?.bell_test && (
        <div
          className="sec-accounting"
          title="Classical Monte-Carlo CHSH diagnostic. S > 2 + 3σ is a model-relative threshold result; this is not a physical Bell test or device-independent certification."
        >
          <div className="sec-row">
            <span className="stat-name">simulated CHSH S</span>
            <span className={`mono ${result.bell_test.certified ? 'sec-ok' : 'sec-warn'}`}>
              {result.bell_test.s.toFixed(3)} ± {result.bell_test.sigma.toFixed(3)}
            </span>
          </div>
          <div className="sec-row">
            <span className="stat-name">model flag</span>
            <span className={`mono ${result.bell_test.certified ? 'sec-ok' : 'sec-warn'}`}>
              {result.bell_test.certified
                ? `S > 2 by ${result.bell_test.margin_sigma.toFixed(1)}σ in this sample`
                : 'S does not clear the model threshold'}
            </span>
          </div>
          <div className="sec-row">
            <span className="stat-name">visibility</span>
            <span className="mono">{(result.bell_test.visibility * 100).toFixed(0)}%</span>
          </div>
          <div className="sec-row">
            <span className="stat-name">pairs tested</span>
            <span className="mono">{result.bell_test.rounds.toLocaleString()}</span>
          </div>
        </div>
      )}
      {result?.security && authentic && result.key_distilled && (
        <div className="sec-accounting" title="Modeled entropy accounting. The LHL bound is shown only for the independent-seed extractor path and is not a hardware or deployment guarantee.">
          <div className="sec-row">
            <span className="stat-name">min-entropy</span>
            <span className="mono">{result.security.min_entropy_bits.toFixed(0)} bits</span>
          </div>
          <div className="sec-row">
            <span className="stat-name">eve −</span>
            <span className="mono">{result.security.eve_bits.toLocaleString()} bits</span>
          </div>
          <div className="sec-row">
            <span className="stat-name">reconcile leak −</span>
            <span className="mono">{result.security.reconciliation_leakage.toLocaleString()} bits</span>
          </div>
          <div className="sec-row">
            <span className="stat-name">extracted</span>
            <span className="mono">{result.security.output_bits}-bit key</span>
          </div>
          <div className="sec-row">
            <span className="stat-name">ε (LHL model)</span>
            <span className="mono">
              {result.security.epsilon === null
                ? 'not claimed (seeded demo)'
                : result.security.epsilon <= 2 ** -300
                  ? '≤ 2⁻³⁰⁰'
                  : result.security.epsilon.toExponential(1)}
            </span>
          </div>
          <div className="sec-row">
            <span className="stat-name">finite-key</span>
            <span className={`mono ${result.security.finite_key_ok ? 'sec-ok' : 'sec-warn'}`}>
              {result.security.finite_key_ok ? 'settled' : 'unresolved'}
            </span>
          </div>
        </div>
      )}
    </div>
  )
}
