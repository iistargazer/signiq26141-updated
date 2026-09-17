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
import { LedgerPanel } from './components/LedgerPanel'
import { EntrySequence, ENTRY_SEEN_KEY } from './components/EntrySequence'

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

/** Dashboard sections; every id doubles as an anchor for the nav rail.
 *  Numbered like paper sections — de-uniforms the page and reads human. */
const SECTIONS = [
  { id: 'channel', label: '01 · Channel' },
  { id: 'vault', label: '02 · Vault' },
  { id: 'transfer', label: '03 · Transfer' },
  { id: 'p2p', label: '04 · P2P' },
  { id: 'attacks', label: '05 · Attacks' },
  { id: 'qds', label: '06 · QDS Lab' },
  { id: 'ledger', label: '07 · Ledger' },
] as const

type SectionId = (typeof SECTIONS)[number]['id']

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

  // Active nav section: driven by scroll position (IntersectionObserver) so
  // the rail highlights whatever the user is actually looking at, and by
  // click (smooth-scroll to the section).
  const [activeSection, setActiveSection] = useState<SectionId>('channel')
  const suppressScrollSpyRef = useRef(false)

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

  // The dashboard's animated backdrop canvas mounts only after the entry
  // sequence is finished — during the intro it would be invisible work.
  const [entryDone, setEntryDone] = useState(() => {
    try {
      return sessionStorage.getItem(ENTRY_SEEN_KEY) === '1'
    } catch {
      return false
    }
  })

  // --- scroll spy ---
  useEffect(() => {
    const observer = new IntersectionObserver(
      (visible) => {
        if (suppressScrollSpyRef.current) return
        const top = visible
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0]
        if (top) setActiveSection(top.target.id as SectionId)
      },
      { rootMargin: '-30% 0px -55% 0px' },
    )
    for (const s of SECTIONS) {
      const el = document.getElementById(s.id)
      if (el) observer.observe(el)
    }
    return () => observer.disconnect()
  }, [])

  const jumpTo = (id: SectionId) => {
    setActiveSection(id)
    suppressScrollSpyRef.current = true
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    window.setTimeout(() => {
      suppressScrollSpyRef.current = false
    }, 700)
  }

  return (
    <>
      {/* ---- boot/entry screen (once per session; #entry forces a replay —
           handy for recording the demo video). While it is up, the
           dashboard backdrop canvas is UNMOUNTED: nothing animates
           behind the overlay, so the first paint stays cheap. ---- */}
      <EntrySequence
        forceReplay={location.hash === '#entry'}
        onFinished={() => setEntryDone(true)}
      />

      {/* ---- fixed background: quantum lattice canvas + nebula wash ---- */}
      {entryDone && <QuantumBackdrop running={running} />}

      {/* ---- quiet atmosphere: static grain + vignette (no animation) ---- */}
      <div className="atmo-noise" aria-hidden />
      <div className="atmo-vignette" aria-hidden />

      <header className="topbar">
        <div className="topbar-inner">
          <div className="brand">
            <span className="brand-mark" aria-hidden>
              <svg viewBox="0 0 24 24" width="22" height="22" fill="none">
                <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.5" />
                <ellipse cx="12" cy="12" rx="9" ry="3.6" stroke="currentColor" strokeWidth="1.2" opacity="0.65" />
                <ellipse cx="12" cy="12" rx="3.6" ry="9" stroke="currentColor" strokeWidth="1.2" opacity="0.65" />
                <circle cx="12" cy="12" r="2" fill="currentColor" />
              </svg>
            </span>
            <div>
              <div className="brand-name">SigniQ</div>
              <div className="brand-sub">Quantum-Secured Document Pipeline · SIH26141</div>
            </div>
          </div>
          <nav className="section-nav" aria-label="Dashboard sections">
            {SECTIONS.map((s) => (
              <button
                key={s.id}
                className={`nav-tab ${activeSection === s.id ? 'nav-tab-active' : ''}`}
                onClick={() => jumpTo(s.id)}
              >
                {s.label}
              </button>
            ))}
          </nav>
          <div className="topbar-right">
            <span
              className={`pill ${backendUp === null ? 'pill-gray' : backendUp ? 'pill-green' : 'pill-red'}`}
              title={backendUp ? 'API reachable' : 'API unreachable'}
            >
              <span className="pill-dot" /> {backendUp === null ? 'checking' : backendUp ? 'API online' : 'API offline'}
            </span>
            <button className="btn btn-primary" onClick={handleRun} disabled={running || backendUp === false}>
              {running ? 'Running…' : customMode ? 'Run Custom Scenario' : 'Run Secure + Attack'}
            </button>
          </div>
        </div>
      </header>

      <AuthBar onLog={pushLog} onUserChange={() => {}} />

      {error && <div className="error-banner">{error}</div>}

      {/* ---- hero: asymmetric editorial intro (not a centered SaaS banner) ---- */}
      <section className="hero" aria-label="Project introduction">
        <div className="hero-side" aria-hidden>
          <span className="hero-sec-mark">01</span>
        </div>
        <div className="hero-copy">
          <div className="hero-eyebrow">Smart India Hackathon · Problem Statement 26141</div>
          <h2 className="hero-title">
            Documents sealed by <span className="hero-accent">quantum physics</span>, proven by
            mathematics.
          </h2>
          <p className="hero-sub">
            Six-state quantum key distribution detects every eavesdropper, teleportation-based
            quantum digital signatures authenticate every document, AES-256-GCM seals it, and a
            Merkle ledger proves nothing was rewritten — end to end, laptop to laptop.
          </p>
          <div className="hero-foot">
            <div className="hero-badges">
              <span className="chip chip-blue">Six-State QKD</span>
              <span className="chip chip-violet">Teleportation QDS</span>
              <span className="chip chip-green">AES-256-GCM</span>
              <span className="chip chip-gray">Merkle ledger</span>
              <span className="chip chip-gray">P2P + relay</span>
            </div>
            <div className="hero-credits" role="note" aria-label="Team credits">
              <div className="credits-flame" aria-hidden>
                <svg viewBox="0 0 24 24" width="22" height="22" fill="none">
                  <path
                    d="M12 2.5c1.8 2.6 1.2 4.4.2 5.9-.9 1.4-1.9 2.8-1.4 4.9.4 1.7 1.8 2.7 1.8 2.7s-.5-1.6.4-3c.7-1.1 1.9-1.7 2.3-3.3 1.5 1.6 2.6 3.9 2.2 6.2-.5 2.7-2.8 4.6-5.5 4.6s-5-2-5.4-4.7C6 12 9.3 9.4 9.8 6.4c.1-.9 0-1.9-.2-2.9 1 .1 1.8.4 2.4 1Z"
                    stroke="currentColor"
                    strokeWidth="1.4"
                    strokeLinejoin="round"
                  />
                  <circle cx="12" cy="17" r="1.6" fill="currentColor" opacity="0.85" />
                </svg>
              </div>
              <div>
                <div className="credits-team">Team Prometheus</div>
                <div className="credits-note">crafted the quantum-secured document pipeline</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="channel" className="panel section-anchor">
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

      <div id="vault" className="section-anchor">
        <DocVault onLog={pushLog} />
      </div>

      <div id="transfer" className="section-anchor">
        <TransferPortal onLog={pushLog} />
      </div>

      <div id="p2p" className="section-anchor">
        <PeerTransfer onLog={pushLog} />
      </div>

      <div id="attacks" className="section-anchor">
        <AttackLab onLog={pushLog} />
      </div>

      <div id="qds" className="section-anchor">
        <QdsLab />
      </div>

      <div id="ledger" className="section-anchor">
        <LedgerPanel onLog={pushLog} />
      </div>

      {results.length > 0 && (
        <section id="keys" className="panel section-anchor">
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

/**
 * Fixed full-viewport backdrop: a slow parallax field of drifting photons
 * (entangled pairs — the second dot mirrors the first), plus a faint node
 * lattice. Canvas-based so it never touches layout; blurs to a standstill
 * while a run streams so the charts stay the visual focus.
 */
function QuantumBackdrop({ running }: { running: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let raf = 0
    let width = window.innerWidth
    let height = window.innerHeight
    // Render at device pixels (capped) — CSS size stays plain pixels.
    const dpr = Math.min(window.devicePixelRatio || 1, 1.75)

    interface Photon {
      x: number
      y: number
      vx: number
      vy: number
      r: number
      tone: 0 | 1 // 0 = candle-gold, 1 = firefly verdigris
      phase: number
    }
    const rand = (a: number, b: number) => a + Math.random() * (b - a)

    // Pre-rendered glow sprite, one per tone: the old loop built two
    // radial GRADIENTS per photon per frame (~90 gradient objects/frame,
    // the main launch-lag source). drawImage of a cached sprite is ~10x
    // cheaper and visually identical for soft glows.
    const spriteFor = (rgb: string) => {
      const s = document.createElement('canvas')
      const R = 32
      s.width = s.height = R * 2
      const c = s.getContext('2d')
      if (c) {
        const g = c.createRadialGradient(R, R, 0, R, R, R)
        g.addColorStop(0, `rgba(${rgb}, 0.85)`)
        g.addColorStop(0.35, `rgba(${rgb}, 0.28)`)
        g.addColorStop(1, `rgba(${rgb}, 0)`)
        c.fillStyle = g
        c.fillRect(0, 0, R * 2, R * 2)
      }
      return s
    }
    const sprites = [spriteFor('217, 168, 81'), spriteFor('143, 199, 168')]

    // Particle density scales with viewport, hard-capped for low-end GPUs.
    const countFor = () =>
      Math.max(24, Math.min(46, Math.round((width * height) / 42000)))

    const spawn = (): Photon => ({
      x: rand(0, width),
      y: rand(0, height),
      vx: rand(-0.12, 0.12),
      vy: rand(-0.08, 0.08),
      r: rand(0.8, 2.1),
      tone: Math.random() < 0.62 ? 0 : 1,
      phase: rand(0, Math.PI * 2),
    })
    let photons: Photon[] = []

    const nodeGrid = 90
    let nodes: Array<[number, number]> = []
    const buildNodes = () => {
      nodes = []
      for (let gx = nodeGrid / 2; gx < width; gx += nodeGrid)
        for (let gy = nodeGrid / 2; gy < height; gy += nodeGrid) nodes.push([gx, gy])
    }

    const resize = () => {
      width = window.innerWidth
      height = window.innerHeight
      canvas.width = Math.round(width * dpr)
      canvas.height = Math.round(height * dpr)
      canvas.style.width = `${width}px`
      canvas.style.height = `${height}px`
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      const want = countFor()
      if (photons.length > want) photons.length = want
      while (photons.length < want) photons.push(spawn())
      buildNodes()
    }
    resize()
    window.addEventListener('resize', resize, { passive: true })

    let last = performance.now()
    const frame = (now: number) => {
      const dt = Math.min((now - last) / 16.7, 3)
      last = now
      ctx.clearRect(0, 0, width, height)

      // faint lattice nodes at grid intersections
      ctx.fillStyle = 'rgba(143, 199, 168, 0.05)'
      for (const [gx, gy] of nodes) ctx.fillRect(gx - 0.5, gy - 0.5, 1.2, 1.2)

      // entangled pairs: photon + its mirror partner, from cached sprites
      for (let i = 0; i < photons.length; i++) {
        const p = photons[i]
        p.x += p.vx * dt * (running ? 0.25 : 1)
        p.y += p.vy * dt * (running ? 0.25 : 1)
        p.phase += 0.02 * dt
        if (p.x < -10) p.x = width + 10
        if (p.x > width + 10) p.x = -10
        if (p.y < -10) p.y = height + 10
        if (p.y > height + 10) p.y = -10

        const tw = 0.55 + 0.45 * Math.sin(p.phase)
        const spr = sprites[p.tone]
        const size = p.r * 6
        ctx.globalAlpha = 0.55 * tw
        ctx.drawImage(spr, p.x - size / 2, p.y - size / 2, size, size)
        // mirrored entangled partner, drifting diagonally opposite
        ctx.globalAlpha = 0.32 * tw
        ctx.drawImage(
          spr,
          width - p.x - size * 0.4,
          height - p.y - size * 0.4,
          size * 0.8,
          size * 0.8,
        )
      }
      ctx.globalAlpha = 1

      raf = requestAnimationFrame(frame)
    }
    raf = requestAnimationFrame(frame)
    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
    }
  }, [running])

  return <canvas ref={canvasRef} className="quantum-backdrop" aria-hidden />
}
