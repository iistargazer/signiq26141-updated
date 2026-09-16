import { useCallback, useEffect, useRef, useState } from 'react'
import { discoverApiBase, healthCheck, runSweep, setApiBase, startRun } from './api'
import type { RunEvent, ScenarioResult } from './api'
import { useRunStream } from './useRunStream'
import { StatusCard } from './components/StatusCard'
import { LiveMonitor } from './components/LiveMonitor'
import { SweepPanel } from './components/SweepPanel'
import { QdsLab } from './components/QdsLab'
import { DocVault } from './components/DocVault'
import { TransferPortal } from './components/TransferPortal'
import { PeerTransfer } from './components/PeerTransfer'
import { AuthBar } from './components/AuthBar'
import { AttackLab } from './components/AttackLab'

export interface LiveScenario {
  processed: number
  total: number
  sifted: number
  mismatches: number
  qber: number
  threshold: number
  points: { processed: number; qber: number; threshold: number }[]
}

const SCENARIO_LABELS: Record<string, string> = {
  secure: 'Secure Channel',
  attack: 'Intercept-Resend Attack',
  custom: 'Custom Intercept Ratio',
}

export default function App() {
  // --- experiment parameters ---
  const [keyLength, setKeyLength] = useState(20000)
  const [threshold, setThreshold] = useState(0.15)
  const [customMode, setCustomMode] = useState(false)
  const [eveRatio, setEveRatio] = useState(0.3)
  const [noiseRate, setNoiseRate] = useState(0.0)
  const [relayHops, setRelayHops] = useState(0)
  const [paceMs, setPaceMs] = useState(6)
  const [seed, setSeed] = useState('')
  const [lastSeed, setLastSeed] = useState<number | null>(null)
  const [message, setMessage] = useState('SIH26141 Sensitive Financial Transaction Data')

  // --- run state ---
  const [running, setRunning] = useState(false)
  const [results, setResults] = useState<ScenarioResult[]>([])
  const [live, setLive] = useState<Record<string, LiveScenario>>({})
  const [log, setLog] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [backendUp, setBackendUp] = useState<boolean | null>(null)

  // --- sweep state ---
  const [sweepLoading, setSweepLoading] = useState(false)
  const [sweep, setSweep] = useState<{ ratio: number; qber: number; threshold: number; theory: number }[]>([])

  const acceptingRef = useRef(false)
  const runIdRef = useRef<number | null>(null)

  const pushLog = useCallback((line: string) => {
    const ts = new Date().toLocaleTimeString()
    setLog((prev) => [`${ts}  ${line}`, ...prev].slice(0, 8))
  }, [])

  useRunStream((ev: RunEvent) => {
    if (!acceptingRef.current) return
    if (runIdRef.current !== null && ev.run_id !== runIdRef.current) return

    if (ev.type === 'progress') {
      setLive((prev) => {
        const cur = prev[ev.scenario] ?? {
          processed: 0,
          total: ev.total,
          sifted: 0,
          mismatches: 0,
          qber: 0,
          threshold: 1,
          points: [],
        }
        const points = [...cur.points, { processed: ev.processed, qber: ev.qber, threshold: ev.threshold }]
        if (points.length > 600) points.splice(0, points.length - 600)
        return {
          ...prev,
          [ev.scenario]: {
            processed: ev.processed,
            total: ev.total,
            sifted: ev.sifted,
            mismatches: ev.mismatches,
            qber: ev.qber,
            threshold: ev.threshold,
            points,
          },
        }
      })
    } else if (ev.type === 'result') {
      const label = SCENARIO_LABELS[ev.result.scenario] ?? ev.result.scenario
      const verdict = ev.result.is_authentic
        ? `AUTHENTIC (QBER ${(ev.result.qber * 100).toFixed(2)}%)`
        : `THREAT FLAGGED (QBER ${(ev.result.qber * 100).toFixed(2)}% > ${(ev.result.dynamic_threshold * 100).toFixed(2)}%)`
      pushLog(`${label}: ${verdict}`)
    } else if (ev.type === 'done') {
      acceptingRef.current = false
      setRunning(false)
      pushLog(`Run #${ev.run_id} finished`)
    }
  })

  // Backend health polling with automatic fallback-port discovery:
  // if the same-origin health check fails, probe the port manifest and the
  // adjacent ports so the dashboard finds a server that fell back off 8080.
  useEffect(() => {
    let alive = true
    const check = async () => {
      try {
        await healthCheck()
        if (!alive) return
        setBackendUp(true)
      } catch {
        try {
          const apiBase = await discoverApiBase()
          if (!alive) return
          setApiBase(apiBase)
          setBackendUp(true)
        } catch {
          if (alive) setBackendUp(false)
        }
      }
    }
    check()
    const t = setInterval(check, 10000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [])

  const parseSeed = (): number | undefined => {
    const t = seed.trim()
    if (t === '') return undefined
    const n = Number(t)
    return Number.isFinite(n) ? n : undefined
  }

  // "Seed (blank = random)" must actually be random: if a caller passes a
  // hardcoded fallback here, charts stop responding to parameter changes and
  // every sweep looks identical. Echo the server's actually-used seed so the
  // event log shows why a run was (or wasn't) reproducible.
  const describeSeed = (used?: number): string => {
    setLastSeed(used ?? null)
    return used !== undefined ? `seed ${used}` : 'random seed'
  }

  const handleRun = async () => {
    setError(null)
    setResults([])
    setLive({})
    setRunning(true)
    acceptingRef.current = true
    runIdRef.current = null
    try {
      const resp = await startRun({
        key_length: keyLength,
        base_threshold: threshold,
        intercept_ratio: customMode ? eveRatio : undefined,
        noise_rate: noiseRate > 0 ? noiseRate : undefined,
        relay_hops: relayHops > 0 ? relayHops : undefined,
        message: message || undefined,
        pace_ms: paceMs,
        seed: parseSeed(),
      })
      runIdRef.current = resp.run_id
      setResults(resp.results)
      const ok = resp.results.filter((r) => r.is_authentic).length
      pushLog(
        `Run #${resp.run_id}: ${ok}/${resp.results.length} scenarios authentic · ` +
          `${describeSeed(resp.seed)} · ${keyLength.toLocaleString()} qubits · ` +
          `threshold ${(threshold * 100).toFixed(0)}%`,
      )
    } catch (e) {
      acceptingRef.current = false
      setRunning(false)
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const handleSweep = async () => {
    setSweepLoading(true)
    setError(null)
    try {
      const resp = await runSweep({
        intercept_ratios: Array.from({ length: 11 }, (_, i) => i / 10),
        key_length: keyLength,
        base_threshold: threshold,
        noise_rate: noiseRate > 0 ? noiseRate : undefined,
        relay_hops: relayHops > 0 ? relayHops : undefined,
        seed: parseSeed(),
      })
      setSweep(
        resp.sweep.map((s) => ({
          ratio: s.intercept_ratio,
          qber: s.qber,
          threshold: s.dynamic_threshold,
          theory: s.intercept_ratio / 3,
        })),
      )
      pushLog(
        `Sweep complete: ${resp.sweep.length} intercept ratios · ` +
          `${describeSeed(resp.seed)} · ${keyLength.toLocaleString()} qubits`,
      )
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setSweepLoading(false)
    }
  }

  const visibleScenarios = customMode ? ['custom'] : ['secure', 'attack']

  return (
    <>
      <header className="header">
        <div>
          <h1>
            Quantum-Secured Pipeline <span className="logo-q">⚛</span>
          </h1>
          <p className="subtitle">SIH26141 · Six-State QKD · Hoeffding-Bound Intrusion Detection</p>
        </div>
        <div className="header-right">
          <AuthBar onLog={pushLog} onUserChange={() => {}} />
          <span
            className={`pill ${backendUp === null ? 'pill-gray' : backendUp ? 'pill-green' : 'pill-red'}`}
          >
            {backendUp === null ? 'checking…' : backendUp ? '● API online' : '● API offline'}
          </span>
          <button className="btn btn-primary" onClick={handleRun} disabled={running || backendUp === false}>
            {running ? 'Running…' : customMode ? 'Run Custom Scenario' : 'Run Secure + Attack'}
          </button>
        </div>
      </header>

      {error && <div className="error-banner">⚠ {error}</div>}

      <section className="panel">
        <div className="panel-title">Experiment Parameters</div>
        <div className="controls-grid">
          <label className="control">
            <span>
              Key length <b>{keyLength.toLocaleString()}</b> qubits
            </span>
            <input
              type="range"
              min={1000}
              max={100000}
              step={1000}
              value={keyLength}
              onChange={(e) => setKeyLength(Number(e.target.value))}
            />
          </label>
          <label className="control">
            <span>
              Base QBER threshold <b>{(threshold * 100).toFixed(0)}%</b>
            </span>
            <input
              type="range"
              min={0}
              max={0.5}
              step={0.01}
              value={threshold}
              onChange={(e) => setThreshold(Number(e.target.value))}
            />
          </label>
          <label className="control">
            <span>
              Streaming pace <b>{paceMs} ms</b>/batch
            </span>
            <input
              type="range"
              min={0}
              max={20}
              step={1}
              value={paceMs}
              onChange={(e) => setPaceMs(Number(e.target.value))}
            />
          </label>
          <label className="control">
            <span>
              Fiber noise <b>{(noiseRate * 100).toFixed(0)}%</b>
              {noiseRate > 0 && <span className="chip chip-amber chip-sm">degradation filter</span>}
            </span>
            <input
              type="range"
              min={0}
              max={0.12}
              step={0.005}
              value={noiseRate}
              onChange={(e) => setNoiseRate(Number(e.target.value))}
            />
          </label>
          <label className="control">
            <span>
              Relay hops <b>{relayHops}</b>
              {relayHops > 0 && <span className="chip chip-blue chip-sm">{relayHops + 1} links</span>}
            </span>
            <input
              type="range"
              min={0}
              max={4}
              step={1}
              value={relayHops}
              onChange={(e) => setRelayHops(Number(e.target.value))}
            />
          </label>
          <label className="control control-toggle">
            <span>Custom attack ratio</span>
            <input
              type="checkbox"
              checked={customMode}
              onChange={(e) => setCustomMode(e.target.checked)}
            />
          </label>
          {customMode && (
            <label className="control">
              <span>
                Eve intercept ratio <b>{(eveRatio * 100).toFixed(0)}%</b> of qubits
              </span>
              <input
                type="range"
                min={0}
                max={1}
                step={0.05}
                value={eveRatio}
                onChange={(e) => setEveRatio(Number(e.target.value))}
                disabled={!customMode}
              />
            </label>
          )}
          <label className="control">
            <span>Seed (blank = random)</span>
            <input
              type="number"
              placeholder={lastSeed !== null ? `last run: ${lastSeed}` : 'random'}
              title={
                lastSeed !== null
                  ? `Last run used seed ${lastSeed} — type it in to reproduce that exact result`
                  : 'Blank = fresh randomness each run; type a number to get reproducible results'
              }
              value={seed}
              onChange={(e) => setSeed(e.target.value)}
            />
          </label>
          <label className="control control-wide">
            <span>Authenticated message</span>
            <input type="text" value={message} onChange={(e) => setMessage(e.target.value)} />
          </label>
        </div>
      </section>

      <section className="cards-row">
        {visibleScenarios.map((name) => {
          const result = results.find((r) => r.scenario === name)
          return (
            <StatusCard
              key={name}
              title={SCENARIO_LABELS[name]}
              progress={live[name]}
              result={result}
              streaming={running && !result}
            />
          )
        })}
      </section>

      <LiveMonitor live={live} log={log} running={running} baseThreshold={threshold} />

      <SweepPanel data={sweep} loading={sweepLoading} onRun={handleSweep} />

      <DocVault onLog={pushLog} />

      <TransferPortal onLog={pushLog} />

      <PeerTransfer onLog={pushLog} />

      <AttackLab onLog={pushLog} />

      <QdsLab />

      {results.length > 0 && (
        <section className="panel">
          <div className="panel-title">Key Material &amp; Message Authentication</div>
          {results.map((r) => (
            <div key={r.scenario} className="crypto-row">
              <div className="crypto-head">
                <b>{SCENARIO_LABELS[r.scenario] ?? r.scenario}</b>
                <span className={`chip ${r.is_authentic ? 'chip-green' : 'chip-red'}`}>
                  {r.is_authentic ? '✓ secure key established' : '✗ key distillation aborted'}
                </span>
              </div>
              {r.derived_secret ? (
                <div className="crypto-lines">
                  <div>
                    <span className="k">Derived secret (SHA-256 PA):</span>
                    <code>{r.derived_secret}</code>
                  </div>
                  {r.hmac_tag && (
                    <div>
                      <span className="k">HMAC-SHA256 tag:</span>
                      <code>{r.hmac_tag}</code>
                      <span className={`chip ${r.hmac_valid ? 'chip-green' : 'chip-red'} chip-sm`}>
                        {r.hmac_valid ? 'verified' : 'invalid'}
                      </span>
                    </div>
                  )}
                </div>
              ) : (
                <div className="crypto-lines muted-line">
                  Channel compromised at {((r.qber) * 100).toFixed(2)}% QBER
                  {r.first_divergence !== null && <> — first divergent sifted bit at index #{r.first_divergence}</>}
                  . No shared secret produced.
                </div>
              )}
            </div>
          ))}
        </section>
      )}

      <footer className="footer">
        Simulated six-state prepare-and-measure protocol · educational prototype — not production
        cryptography.
      </footer>
    </>
  )
}
