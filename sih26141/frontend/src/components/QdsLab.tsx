import { useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine } from 'recharts'
import { qdsApi } from '../api'
import type { ForgeryAnalysis, MetricsReport, QdsOutcome, QdsSetupResponse, QdsSignResponse } from '../api'

const ATTACK_LABELS: Record<string, string> = {
  forgery: 'Forgery (guessed Bell outcomes)',
  impersonation: 'Impersonation (signature transplant)',
  replay: 'Replay (nonce reuse)',
  channel_tampering: 'Channel tampering (qubits disturbed in flight)',
  unauthorized_verification: 'Unauthorized verification (no key material)',
}

function verdictLabel(v: 'acc1' | 'acc0' | 'rej'): string {
  switch (v) {
    case 'acc1':
      return '1-ACC'
    case 'acc0':
      return '0-ACC'
    default:
      return 'REJ'
  }
}

function fmtUs(us: number): string {
  if (us < 1) return `${(us * 1000).toFixed(0)} ns`
  if (us < 1000) return `${us.toFixed(1)} µs`
  return `${(us / 1000).toFixed(2)} ms`
}

function accuracyOf(c: { true_negatives: number; false_positives: number; true_positives: number; false_negatives: number }): number {
  const total = c.true_negatives + c.false_positives + c.true_positives + c.false_negatives
  return total === 0 ? 0 : (c.true_negatives + c.true_positives) / total
}

function detectionRateOf(c: { true_positives: number; false_negatives: number }): number {
  const total = c.true_positives + c.false_negatives
  return total === 0 ? 0 : c.true_positives / total
}

export function QdsLab() {
  const [message, setMessage] = useState('Transfer 100 QCO to account #8841')
  const [keyInfo, setKeyInfo] = useState<QdsSetupResponse | null>(null)
  const [signInfo, setSignInfo] = useState<QdsSignResponse | null>(null)
  const [attackResults, setAttackResults] = useState<QdsOutcome[]>([])
  const [forgery, setForgery] = useState<ForgeryAnalysis | null>(null)
  const [metrics, setMetrics] = useState<MetricsReport | null>(null)
  const [tamperFraction, setTamperFraction] = useState(0.5)
  const [busy, setBusy] = useState<'key' | 'sign' | 'attacks' | 'forgery' | 'metrics' | null>(null)
  const [error, setError] = useState<string | null>(null)

  const initKeys = async () => {
    setBusy('key')
    setError(null)
    try {
      const res = await qdsApi.setup(16, 4)
      setKeyInfo(res)
      setSignInfo(null)
      setAttackResults([])
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  const doSign = async () => {
    setBusy('sign')
    setError(null)
    try {
      if (!keyInfo) await qdsApi.setup(16, 4).then(setKeyInfo)
      const res = await qdsApi.sign(message)
      setSignInfo(res)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  const doAttacks = async () => {
    setBusy('attacks')
    setError(null)
    try {
      setAttackResults(await qdsApi.attacks(tamperFraction))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  const doMetrics = async () => {
    setBusy('metrics')
    setError(null)
    try {
      setMetrics(await qdsApi.metrics(200, 42))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  const doForgery = async () => {
    setBusy('forgery')
    setError(null)
    try {
      setForgery(await qdsApi.forgeryAnalysis())
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  const chartData =
    forgery?.by_lambda.map((p) => ({
      lambda: `λ=${p.lambda}`,
      // log10 display: -39 reads better than 1e-39 on a bar chart
      log10: Math.log10(p.theory),
    })) ?? []

  return (
    <section className="panel">
      <div className="panel-title-row">
        <div className="panel-title">⚛ QDS Signature Lab — Teleportation-based Signing</div>
        <button className="btn btn-ghost" onClick={initKeys} disabled={busy !== null}>
          {busy === 'key' ? 'Generating…' : keyInfo ? 'Regenerate keys' : '1 · Generate quantum keys'}
        </button>
      </div>

      {error && <div className="error-banner">⚠ {error}</div>}

      {keyInfo && (
        <div className="qds-keyinfo">
          <span>
            Key: <b>{keyInfo.qubit_count} qubits</b> × <b>λ={keyInfo.lambda}</b> Bell rounds
          </span>
          <span className="chip chip-green">
            P(forgery) &lt; 10^{Math.ceil(Math.log10(keyInfo.theory_forgery_probability))}
          </span>
          <code className="commitment" title="Public key commitment H(A1‖A2)">
            {keyInfo.key_commitment.slice(0, 24)}…
          </code>
        </div>
      )}

      <div className="qds-sign-row">
        <input
          className="qds-message"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Message to sign"
        />
        <button className="btn btn-primary" onClick={doSign} disabled={busy !== null || !message.trim()}>
          {busy === 'sign' ? 'Teleporting…' : '2 · Sign via teleportation'}
        </button>
      </div>

      {signInfo && (
        <div className="qds-sign-result">
          <div className="qds-badges">
            <span className={`chip ${signInfo.initial_verification_accepted ? 'chip-green' : 'chip-red'}`}>
              {signInfo.initial_verification_accepted ? '✓ Bob verified · 1-ACC (transferable)' : '✗ delivery failed'}
            </span>
            <span className="chip chip-gray">nonce {signInfo.nonce} (single-use)</span>
            <span className="chip chip-gray">
              {signInfo.qubit_count * signInfo.lambda * 2} signature bits
            </span>
          </div>
          <div className="qds-teleport">
            <div className="qds-teleport-title">Teleportation trace (first 6 qubits)</div>
            <table className="qds-table">
              <thead>
                <tr>
                  <th>qubit</th>
                  <th>Bell outcome</th>
                  <th>Pauli correction</th>
                  <th>raw bit</th>
                  <th>corrected</th>
                </tr>
              </thead>
              <tbody>
                {signInfo.teleport_sample.map((t) => (
                  <tr key={t.position}>
                    <td>#{t.position}</td>
                    <td>
                      {String(t.bell_outcome).padStart(2, '0')}
                    </td>
                    <td>
                      <code className="correction">{t.correction}</code>
                    </td>
                    <td>{t.raw_bit}</td>
                    <td>{t.corrected_bit}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="qds-sigbits">
            <span className="k">Signature (correction bits):</span>
            <code>{signInfo.signature_hex.slice(0, 64)}…</code>
          </div>
          <div className="qds-tamper-control">
            <span className="k">
              Tamper fraction <b>{(tamperFraction * 100).toFixed(0)}%</b> of qubits
            </span>
            <input
              type="range"
              min={0}
              max={1}
              step={0.05}
              value={tamperFraction}
              onChange={(e) => setTamperFraction(Number(e.target.value))}
            />
          </div>
          <button className="btn btn-primary" onClick={doAttacks} disabled={busy !== null}>
            {busy === 'attacks' ? 'Attacking…' : '3 · Launch all 5 attacks'}
          </button>
        </div>
      )}

      {attackResults.length > 0 && (
        <div className="qds-attacks">
          {attackResults.map((r) => (
            <div key={r.kind} className={`attack-row ${r.report.accepted ? 'attack-bad' : 'attack-good'}`}>
              <div className="attack-head">
                <b>{ATTACK_LABELS[r.kind] ?? r.kind}</b>
                <span className="chip chip-gray">{verdictLabel(r.report.verdict)}</span>
                <span className={`chip ${r.report.accepted ? 'chip-red' : 'chip-green'}`}>
                  {r.report.accepted ? '✗ accepted (bad!)' : '✓ rejected'}
                </span>
              </div>
              <div className="attack-desc">{r.description}</div>
              <div className="attack-stats">
                {r.report.evaluated === false ? (
                  <>blocked before statistics — nonce/commitment check (see event log)</>
                ) : (
                  <>
                    {r.report.mismatches}/{r.report.total_positions} positions mismatched ·{' '}
                    {(r.report.match_ratio * 100).toFixed(1)}% match ratio
                  </>
                )}
                {r.charlie_agrees !== undefined &&
                  (r.charlie_agrees ? ' · Charlie consensus: ✓ agrees' : ' · Charlie consensus: ✗ rejects')}
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="qds-forgery">
        <div className="panel-title-row">
          <div className="panel-title">Forgery probability analysis</div>
          <button className="btn btn-ghost" onClick={doForgery} disabled={busy !== null}>
            {busy === 'forgery' ? 'Analyzing…' : '4 · Run analysis'}
          </button>
        </div>
        {forgery ? (
          <>
            <p className="panel-hint">
              Whole-signature forgery requires guessing every Bell outcome: P = (1/4)
              <sup>qubits×λ</sup>. Monte-Carlo over {forgery.trials.toLocaleString()} trials
              estimated {forgery.monte_carlo_probability.toExponential(2)} (theory{' '}
              {forgery.theory_probability.toExponential(2)}). Bars show log₁₀(P) — lower is
              harder to forge.
            </p>
            <div className="chart-wrap">
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={chartData} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2a44" />
                  <XAxis dataKey="lambda" stroke="#64748b" tick={{ fontSize: 11 }} />
                  <YAxis
                    stroke="#64748b"
                    tick={{ fontSize: 11 }}
                    domain={[-45, 0]}
                    tickFormatter={(v: number) => `1e${v}`}
                  />
                  <Tooltip
                    contentStyle={{
                      background: '#0d1526',
                      border: '1px solid #1f2a44',
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                    formatter={(v) => `P(forgery) = 10^${Number(v).toFixed(1)}`}
                  />
                  <ReferenceLine y={-30} stroke="#34d399" strokeDasharray="4 4" label={{ value: '128-bit security', fill: '#34d399', fontSize: 10, position: 'insideTopRight' }} />
                  <Bar dataKey="log10" name="log10 P(forgery)" fill="#60a5fa" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </>
        ) : (
          <div className="empty-state">Run the analysis to see forgery probabilities scale with λ.</div>
        )}
      </div>

      <div className="qds-metrics">
        <div className="panel-title-row">
          <div className="panel-title">Performance evaluation (Lap 2 metrics)</div>
          <button className="btn btn-ghost" onClick={doMetrics} disabled={busy !== null}>
            {busy === 'metrics' ? 'Evaluating…' : '5 · Run evaluation'}
          </button>
        </div>
        {metrics ? (
          <>
            <p className="panel-hint">
              Repeatable evaluation (seeded, deterministic): verification accuracy, detection
              rate, false alarms, forgery probability, and wall-clock cost per operation for
              both QDS schemes. No AI/ML — every decision is a threshold rule.
            </p>
            <div className="qds-metrics-grid">
              <div className="qds-metric-card">
                <div className="qds-metric-title">Teleportation QDS</div>
                <div className="qds-metric-rows">
                  <div><span className="k">Verification accuracy</span><b>{(accuracyOf(metrics.teleport.confusion) * 100).toFixed(2)}%</b></div>
                  <div><span className="k">Detection rate</span><b>{(detectionRateOf(metrics.teleport.confusion) * 100).toFixed(2)}%</b></div>
                  <div><span className="k">False positives</span><b>{metrics.teleport.confusion.false_positives}</b></div>
                  <div><span className="k">False negatives</span><b>{metrics.teleport.confusion.false_negatives}</b></div>
                  <div><span className="k">Forgery probability (MC vs theory)</span><b>{metrics.teleport.empirical_forgery_probability.toExponential(1)} / {metrics.teleport.theoretical_forgery_probability.toExponential(1)}</b></div>
                  <div><span className="k">sign / verify</span><b>{fmtUs(metrics.teleport.timing.mean_sign_us)} / {fmtUs(metrics.teleport.timing.mean_verify_us)}</b></div>
                </div>
              </div>
              <div className="qds-metric-card">
                <div className="qds-metric-title">Six-state QDS (Weng et al.)</div>
                <div className="qds-metric-rows">
                  <div><span className="k">Verification accuracy</span><b>{(accuracyOf(metrics.six_state.confusion) * 100).toFixed(2)}%</b></div>
                  <div><span className="k">Detection rate</span><b>{(detectionRateOf(metrics.six_state.confusion) * 100).toFixed(2)}%</b></div>
                  <div><span className="k">False positives</span><b>{metrics.six_state.confusion.false_positives}</b></div>
                  <div><span className="k">False negatives</span><b>{metrics.six_state.confusion.false_negatives}</b></div>
                  <div><span className="k">Per-class detection</span><b>{Object.entries(metrics.six_state.detection_by_class).map(([k, v]) => `${k} ${(v.detected / Math.max(1, v.detected + v.missed) * 100).toFixed(0)}%`).join(' · ')}</b></div>
                  <div><span className="k">sign / verify</span><b>{fmtUs(metrics.six_state.timing.mean_sign_us)} / {fmtUs(metrics.six_state.timing.mean_verify_us)}</b></div>
                </div>
              </div>
            </div>
          </>
        ) : (
          <div className="empty-state">Run the evaluation to measure accuracy, detection rates, false alarms and computational cost.</div>
        )}
      </div>

      <details className="refs-block">
        <summary>Theoretical basis & references</summary>
        <ul>
          <li>
            Gottesman &amp; Chuang (2001), <i>Quantum Digital Signatures</i> — quantum one-way
            functions, the 1-ACC / 0-ACC / REJ verdict semantics, and the transferability
            (non-repudiation) criterion implemented by the Charlie consensus check.
          </li>
          <li>
            Singh et al. (2023), <i>Securing Blockchain Transactions Using Quantum Teleportation
            and Quantum Digital Signature</i> — sign → teleport (EPR pairs, Bell measurement,
            Pauli corrections) → validate-by-mismatch-count pipeline with dual thresholds
            (Ta/Tb ≙ c1/c2); single-use signatures defeating replay/double-spend ≙ nonce ledger.
          </li>
          <li>
            Weng et al. (2021), <i>Secure and Practical Multiparty QDS</i> — six-state Pauli-eigenstate
            encoding with mismatching-rate threshold decisions (the same statistical rule as our
            QKD-layer ThreatDetector); majority-voting consensus among verifiers ≙ transferability check.
          </li>
        </ul>
      </details>
    </section>
  )
}
