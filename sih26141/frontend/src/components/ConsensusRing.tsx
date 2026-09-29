import { useState } from 'react'
import { qdsApi, type RingVerdict, type BoundsReport, type ScenarioResult } from '../api'

/**
 * Feature 3 + 4 — the Multi-Receiver Consensus Verification Ring and the
 * Chernoff–Hoeffding Statistical Confidence visualizer, as one defense-grade
 * section.
 *
 * The ring: Alice's signed document reaches m receivers over independent
 * channels; each verifies independently; k-of-m acceptances unlock. An
 * attacker can be injected onto one member's channel to show quorum
 * tolerance (k of m survives a compromised minority).
 *
 * The visualizer: for an observed mismatch count k over n samples, plots
 * how the rejection threshold narrows with sample size (Hoeffding slack),
 * shows both concentration bounds, and reports the exact binomial p-value
 * of the REJECT verdict — the mathematical answer to "how do you know
 * 0.15 is the right threshold?".
 */

const DEFAULT_MEMBERS = ['bob', 'charlie', 'dave', 'erin', 'frank']

function bandLabel(band: BoundsReport['verdict']['band']): string {
  switch (band) {
    case 'airtight':
      return 'airtight (p < 10⁻⁶)'
    case 'decisive':
      return 'decisive (p < 10⁻³)'
    case 'significant':
      return 'significant (p < 0.05)'
    case 'undersized':
      return 'undersized sample — enlarge n'
  }
}

function CurvePlot({ report }: { report: BoundsReport }) {
  // SVG plot of the threshold curve: x = log n, y = threshold.
  const W = 560
  const H = 180
  const pad = 34
  const ns = report.curve.map((p) => Math.log10(p.n))
  const xMin = Math.min(...ns)
  const xMax = Math.max(...ns)
  const yMax = Math.max(...report.curve.map((p) => p.threshold), report.verdict.threshold, 0.05) * 1.08
  const x = (n: number) => pad + ((Math.log10(n) - xMin) / (xMax - xMin || 1)) * (W - pad - 10)
  const y = (t: number) => H - pad - (t / (yMax || 1)) * (H - pad - 12)
  const path = report.curve.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(p.n).toFixed(1)},${y(p.threshold).toFixed(1)}`).join(' ')
  const area = `${path} L${x(report.curve[report.curve.length - 1].n).toFixed(1)},${y(0)} L${x(report.curve[0].n).toFixed(1)},${y(0)} Z`
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="bounds-plot" role="img" aria-label="Dynamic threshold curve">
      {/* gridlines */}
      {[0.05, 0.1, 0.15, 0.2].filter((t) => t < yMax).map((t) => (
        <g key={t}>
          <line x1={pad} x2={W - 10} y1={y(t)} y2={y(t)} className="bounds-grid" />
          <text x={pad - 4} y={y(t) + 3} className="bounds-tick" textAnchor="end">{(t * 100).toFixed(0)}%</text>
        </g>
      ))}
      <path d={area} className="bounds-area" />
      <path d={path} className="bounds-line" />
      {/* the observed sample */}
      {report.interval.n >= report.curve[0].n && report.interval.n <= report.curve[report.curve.length - 1].n && (
        <g>
          <line
            x1={x(report.interval.n)} x2={x(report.interval.n)}
            y1={y(0)} y2={y(report.interval.hi_hoeffding)}
            className="bounds-sample"
          />
          <circle cx={x(report.interval.n)} cy={y(report.interval.hi_hoeffding)} r={3.5} className="bounds-sample-dot" />
        </g>
      )}
      {/* the threshold line under judgment */}
      <line x1={pad} x2={W - 10} y1={y(report.verdict.threshold)} y2={y(report.verdict.threshold)} className="bounds-threshold-line" />
      <text x={W - 12} y={y(report.verdict.threshold) - 4} className="bounds-tick" textAnchor="end">
        threshold {(report.verdict.threshold * 100).toFixed(0)}%
      </text>
      {/* axis labels */}
      <text x={pad} y={H - 8} className="bounds-tick">n = {report.curve[0].n}</text>
      <text x={W - 10} y={H - 8} className="bounds-tick" textAnchor="end">n = {report.curve[report.curve.length - 1].n}</text>
      <text x={W / 2} y={H - 8} className="bounds-tick" textAnchor="middle">sample size N (log scale) — the threshold narrows like a vice</text>
    </svg>
  )
}

export default function ConsensusRing({ lastRun }: { lastRun?: ScenarioResult[] }) {
  const [k, setK] = useState(3)
  const [m, setM] = useState(5)
  const [attackedMember, setAttackedMember] = useState<number | null>(null)
  const [attackNoise, setAttackNoise] = useState(0.35)
  const [verdict, setVerdict] = useState<RingVerdict | null>(null)
  const [ringBusy, setRingBusy] = useState(false)
  const [ringError, setRingError] = useState<string | null>(null)

  // Bounds explorer state
  const [bK, setBK] = useState(150)
  const [bN, setBN] = useState(1000)
  const [threshold, setThreshold] = useState(0.15)
  const [bounds, setBounds] = useState<BoundsReport | null>(null)
  const [boundsBusy, setBoundsBusy] = useState(false)

  async function runRing() {
    setRingBusy(true)
    setRingError(null)
    try {
      setVerdict(await qdsApi.consensusRing({ k, m, attackedMember, attackNoise, tolerance: 0.1 }))
    } catch (e) {
      setRingError(e instanceof Error ? e.message : String(e))
    } finally {
      setRingBusy(false)
    }
  }

  async function runBounds() {
    setBoundsBusy(true)
    try {
      setBounds(await qdsApi.bounds(Math.max(0, bK), Math.max(1, bN), threshold))
    } finally {
      setBoundsBusy(false)
    }
  }

  /** Live mode: feed the engine THIS dashboard run's actual measurement
   *  statistics (k observed mismatches over the sifted positions) — the
   *  thresholds are evaluated against the measured sample, not manual inputs. */
  function useLastRun(scenario: ScenarioResult) {
    const n = scenario.matching_bases_count
    const k = Math.min(n, Math.round(scenario.qber * n))
    setBK(k)
    setBN(n)
    setThreshold(scenario.dynamic_threshold || threshold)
    setBoundsBusy(true)
    qdsApi.bounds(k, n, scenario.dynamic_threshold || threshold)
      .then(setBounds)
      .finally(() => setBoundsBusy(false))
  }

  const lastRunWithSift = lastRun?.filter((r) => r.matching_bases_count > 0) ?? []

  return (
    <section className="panel" id="consensus-ring">
      <p className="panel-note folio-note">
        Verification leaves the 1-to-1 world: Alice's signature reaches m receivers over
        independent channels, each measures independently, and a k-of-m quorum unlocks.
        Beneath it, the Chernoff–Hoeffding engine displays the exact concentration bounds
        that make every threshold mathematically defensible.
      </p>

      <div className="ring-controls">
        <label className="ring-field">
          <span className="k">quorum k</span>
          <input type="number" min={1} max={m} value={k} onChange={(e) => setK(Math.min(m, Math.max(1, +e.target.value)))} />
        </label>
        <label className="ring-field">
          <span className="k">ring size m</span>
          <input type="number" min={1} max={8} value={m} onChange={(e) => { const v = Math.min(8, Math.max(1, +e.target.value)); setM(v); if (k > v) setK(v) }} />
        </label>
        <label className="ring-field">
          <span className="k">attacked member</span>
          <select value={attackedMember ?? ''} onChange={(e) => setAttackedMember(e.target.value === '' ? null : +e.target.value)}>
            <option value="">none — all honest</option>
            {Array.from({ length: m }, (_, i) => (
              <option key={i} value={i}>{DEFAULT_MEMBERS[i] ?? `receiver-${i}`}</option>
            ))}
          </select>
        </label>
        {attackedMember !== null && (
          <label className="ring-field">
            <span className="k">attack noise {(attackNoise * 100).toFixed(0)}%</span>
            <input type="range" min={5} max={90} value={attackNoise * 100} onChange={(e) => setAttackNoise(+e.target.value / 100)} />
          </label>
        )}
        <button className="btn-primary" onClick={runRing} disabled={ringBusy}>
          {ringBusy ? 'measuring…' : 'Run consensus ring'}
        </button>
      </div>
      {ringError && <div className="verdict-bad ring-error">{ringError}</div>}

      {verdict && (
        <div className="ring-result">
          <div className={`ring-headline ${verdict.quorum_ok ? 'verdict-good' : 'verdict-bad'}`}>
            {verdict.note}
          </div>
          <div className="ring-stats">
            <span className="chip">quorum {verdict.accepted_count}/{verdict.members_queried} ≥ k = {verdict.required}</span>
            <span className="chip">unlock {verdict.quorum_ok ? 'granted' : 'refused'}</span>
            <span className="chip">transfer grade {verdict.transfer_grade ? 'trusted' : 'refused'}</span>
            <span className="chip">{verdict.transferable_count} transferable</span>
          </div>
          <div className="ring-members">
            {verdict.members.map((mem, i) => (
              <div key={mem.name} className={`ring-member ${mem.accepted ? 'member-ok' : 'member-bad'}`}>
                <div className="member-name">
                  <span className="member-rank">{DEFAULT_MEMBERS[i] ?? mem.name}</span>
                  <span className={`member-verdict ${mem.accepted ? '' : 'member-verdict-bad'}`}>
                    {mem.report.verdict.toUpperCase()}
                  </span>
                </div>
                <div className="member-meta">
                  <span>noise {(mem.channel_noise * 100).toFixed(1)}%</span>
                  <span>mismatch {(mem.report.match_ratio * 100).toFixed(1)}%</span>
                  <span>{mem.transferable ? 'transferable' : 'local only'}</span>
                </div>
                <div className="member-reason">{mem.report.reason}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="subpanel-title">Statistical confidence — Chernoff · Hoeffding · exact binomial</div>
      <div className="ring-controls">
        <label className="ring-field">
          <span className="k">mismatches k</span>
          <input type="number" min={0} value={bK} onChange={(e) => setBK(Math.max(0, +e.target.value))} />
        </label>
        <label className="ring-field">
          <span className="k">sample n</span>
          <input type="number" min={1} max={2000000} value={bN} onChange={(e) => setBN(Math.max(1, +e.target.value))} />
        </label>
        <label className="ring-field">
          <span className="k">threshold {(threshold * 100).toFixed(0)}%</span>
          <input type="range" min={1} max={40} value={threshold * 100} onChange={(e) => setThreshold(+e.target.value / 100)} />
        </label>
        <button className="btn-primary" onClick={runBounds} disabled={boundsBusy}>
          {boundsBusy ? 'computing…' : 'Compute bounds'}
        </button>
      </div>
      {lastRunWithSift.length > 0 && (
        <div className="bounds-live-row">
          <span className="k">from the last QKD run:</span>
          {lastRunWithSift.map((r) => {
            const k = Math.round(r.qber * r.matching_bases_count)
            return (
              <button
                key={r.scenario}
                className="chip chip-live"
                onClick={() => useLastRun(r)}
                title={`Feed the engine this scenario's REAL numbers: ${k} mismatches over ${r.matching_bases_count} sifted positions (measured, not typed)`}
              >
                {r.scenario} · k={k}, n={r.matching_bases_count}
              </button>
            )
          })}
        </div>
      )}

      {bounds && (
        <div className="bounds-result">
          <CurvePlot report={bounds} />
          <div className="ring-stats">
            <span className="chip">p̂ = {(bounds.interval.p_hat * 100).toFixed(2)}%</span>
            <span className="chip">Hoeffding ≤ {(bounds.interval.hi_hoeffding * 100).toFixed(2)}%</span>
            <span className="chip">Chernoff ≤ {(bounds.interval.hi_chernoff * 100).toFixed(2)}%</span>
            <span className="chip">Chernoff sharper ×{bounds.chernoff_gain.toFixed(1)}</span>
            <span className="chip">confidence {(bounds.interval.confidence * 100).toFixed(1)}%</span>
          </div>
          <div className={`verdict-line ${bounds.verdict.band === 'undersized' ? '' : 'verdict-good'}`}>
            {bounds.verdict.band === 'undersized'
              ? `The observation is statistically consistent with an honest channel at ${(bounds.verdict.threshold * 100).toFixed(0)}% (p = ${bounds.verdict.p_value.toExponential(2)}) — this sample cannot separate honesty from attack; enlarge n.`
              : `An honest channel at ${(bounds.verdict.threshold * 100).toFixed(0)}% would produce ≥ ${bounds.verdict.k} mismatches with probability ${bounds.verdict.p_value.toExponential(2)} — the rejection is ${bandLabel(bounds.verdict.band)}.`}
          </div>
        </div>
      )}

      <details className="refs-block">
        <summary>Theoretical basis & references</summary>
        <ul>
          <li>
            Hoeffding (1963), <i>Probability Inequalities for Sums of Bounded Random Variables</i> —
            the distribution-free additive slack ε(n, δ) = √(ln(2/δ)/2n) behind the narrowing
            threshold curve.
          </li>
          <li>
            Chernoff (1952), <i>A Measure of Asymptotic Efficiency for Tests of a Hypothesis Based
            on the Sum of Observations</i> — the multiplicative bound that is dramatically tighter
            for small mismatch rates.
          </li>
          <li>
            Gottesman &amp; Chuang (2001) transferability semantics — each ring member's 1-ACC /
            0-ACC / REJ verdict; the transfer gate requires ≥ k transfer-grade acceptances so a
            forwarded signature is guaranteed to verify at any second verifier.
          </li>
          <li>
            Multi-party QDS (Weng et al. 2021) — majority-voting consensus among verifiers,
            generalized here to a cryptographic k-of-m quorum over independent channels.
          </li>
        </ul>
      </details>
    </section>
  )
}
