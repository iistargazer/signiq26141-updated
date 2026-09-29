import { useCallback, useEffect, useRef, useState } from 'react'
import { discoverApiBase, getAuthUsername, healthCheck, runSweep, setApiBase, startRun } from './api'
import type { RunEvent, ScenarioResult } from './api'
import { useRunStream } from './useRunStream'
import { sliderFillStyle } from './sliderFill'
import { StatusCard } from './components/StatusCard'
import { LiveMonitor } from './components/LiveMonitor'
import { SweepPanel } from './components/SweepPanel'
import { NoiseVsEvePanel, type NoiseEveCondition } from './components/NoiseVsEvePanel'
import { BlindChallenge } from './components/BlindChallenge'
import {
  GuidedRun,
  GUIDED_RUN_STEPS,
  type GuidedRunAction,
} from './components/GuidedRun'
import { QdsLab } from './components/QdsLab'
import ConsensusRing from './components/ConsensusRing'
import { DocVault } from './components/DocVault'
import { TransferPortal } from './components/TransferPortal'
import { PeerTransfer } from './components/PeerTransfer'
import { AuthBar } from './components/AuthBar'
import { AttackLab } from './components/AttackLab'
import { LedgerPanel } from './components/LedgerPanel'
import { EntrySequence, ENTRY_SEEN_KEY } from './components/EntrySequence'
import { TeamFlame, TeamDossier } from './components/Team'

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

const MAX_CHART_POINTS = 240
const LIVE_RENDER_INTERVAL_MS = 80

type ProgressEvent = Extract<RunEvent, { type: 'progress' }>
type ChartPoint = LiveScenario['points'][number]

function appendChartPoints(points: ChartPoint[], incoming: ChartPoint[]): ChartPoint[] {
  const combined = [...points, ...incoming]
  if (combined.length <= MAX_CHART_POINTS) return combined

  // Keep an even sample across the full run, including the latest point.
  const stride = (combined.length - 1) / (MAX_CHART_POINTS - 1)
  return Array.from({ length: MAX_CHART_POINTS }, (_, index) =>
    combined[Math.round(index * stride)],
  )
}

/** Batch SSE samples into one immutable snapshot per scenario. */
function mergeLiveProgress(
  previous: Record<string, LiveScenario>,
  scenario: string,
  events: ProgressEvent[],
): Record<string, LiveScenario> {
  const latest = events[events.length - 1]
  const current = previous[scenario]
  const points = appendChartPoints(
    current?.points ?? [],
    events.map(({ processed, qber, threshold }) => ({ processed, qber, threshold })),
  )
  return {
    ...previous,
    [scenario]: {
      processed: latest.processed,
      total: latest.total,
      sifted: latest.sifted,
      mismatches: latest.mismatches,
      qber: latest.qber,
      threshold: latest.threshold,
      points,
    },
  }
}

/** Keep every useful chart sample but update React/Recharts at most every 80 ms. */
function useThrottledRunProgress() {
  const [live, setLive] = useState<Record<string, LiveScenario>>({})
  const pending = useRef(new Map<string, ProgressEvent[]>())
  const flushTimer = useRef<ReturnType<typeof window.setTimeout> | null>(null)
  const lastFlush = useRef(0)

  const flush = useCallback(() => {
    if (flushTimer.current !== null) window.clearTimeout(flushTimer.current)
    flushTimer.current = null
    const updates = [...pending.current.entries()]
    pending.current.clear()
    if (updates.length === 0) return

    setLive((previous) => updates.reduce(
      (next, [scenario, events]) => mergeLiveProgress(next, scenario, events),
      previous,
    ))
    lastFlush.current = performance.now()
  }, [])

  const enqueue = useCallback((event: ProgressEvent) => {
    const scenarioEvents = pending.current.get(event.scenario) ?? []
    scenarioEvents.push(event)
    pending.current.set(event.scenario, scenarioEvents)
    const wait = LIVE_RENDER_INTERVAL_MS - (performance.now() - lastFlush.current)
    if (wait <= 0) {
      flush()
    } else if (flushTimer.current === null) {
      flushTimer.current = window.setTimeout(flush, wait)
    }
  }, [flush])

  const reset = useCallback(() => {
    if (flushTimer.current !== null) window.clearTimeout(flushTimer.current)
    flushTimer.current = null
    pending.current.clear()
    lastFlush.current = 0
    setLive({})
  }, [])

  useEffect(() => () => {
    if (flushTimer.current !== null) window.clearTimeout(flushTimer.current)
  }, [])

  return { live, enqueue, flush, reset }
}

/** Dashboard sections; every id doubles as an anchor for the nav rail.
 *  Numbered like paper sections — de-uniforms the page and reads human. */
const SECTIONS = [
  { id: 'channel', label: 'Channel' },
  { id: 'noise-study', label: 'Noise vs Eve' },
  { id: 'challenge', label: 'Diagnosis' },
  { id: 'vault', label: 'Vault' },
  { id: 'transfer', label: 'Transfer' },
  { id: 'p2p', label: 'Peers' },
  { id: 'attacks', label: 'Attack lab' },
  { id: 'qds', label: 'Signatures' },
  { id: 'consensus', label: 'Consensus' },
  { id: 'ledger', label: 'Ledger' },
] as const

type SectionId = (typeof SECTIONS)[number]['id']

const REPRODUCIBLE_RUN_PRESET = {
  keyLength: 20_000,
  threshold: 0.15,
  eveRatio: 0.3,
  noiseRate: 0,
  relayHops: 0,
  paceMs: 6,
  seed: 26141,
  message: 'SigniQ sample message — verifying the document seal.',
} as const

interface RunEvidenceReceipt {
  runId: number
  seed: number
  completedAt: string
  keyLength: number
  threshold: number
  noiseRate: number
  relayHops: number
  results: ScenarioResult[]
}

function formatTailProbability(value: number | undefined): string {
  if (value === undefined || !Number.isFinite(value)) return 'not reported'
  return value === 0 ? '< 1e-308' : value.toExponential(2)
}

function runReceiptMarkdown(receipt: RunEvidenceReceipt): string {
  const rows = receipt.results.map((result) => {
    const bounds = result.statistical_bounds
    const mismatches = bounds?.interval.k ?? Math.round(result.qber * result.matching_bases_count)
    const verdict = result.key_distilled
      ? 'accepted; key distilled'
      : result.is_authentic
        ? 'within decision line; no key distilled'
        : 'decision line exceeded; no key distilled'
    const inference = result.is_authentic ? 'within configured decision line' : bounds?.verdict.band ?? 'not reported'
    const bell = result.bell_test
      ? `simulated S=${result.bell_test.s.toFixed(3)} (${result.bell_test.certified ? 'model threshold cleared' : 'model threshold not cleared'})`
      : 'not reported'
    return `| ${SCENARIO_LABELS[result.scenario] ?? result.scenario} | ${(result.intercept_ratio * 100).toFixed(0)}% | ${(result.qber * 100).toFixed(3)}% | ${(result.dynamic_threshold * 100).toFixed(2)}% | ${mismatches}/${result.matching_bases_count} | ${formatTailProbability(bounds?.verdict.p_value)} | ${inference} | ${verdict} | ${bell} |`
  })

  return [
    '# SigniQ — Reproducible run receipt',
    '',
    `- Run: #${receipt.runId}`,
    `- Completed: ${new Date(receipt.completedAt).toISOString()}`,
    `- QKD simulator seed: ${receipt.seed}`,
    `- Qubit budget: ${receipt.keyLength.toLocaleString()}`,
    `- Base threshold: ${(receipt.threshold * 100).toFixed(1)}%`,
    `- Fiber noise: ${(receipt.noiseRate * 100).toFixed(1)}% · relay hops: ${receipt.relayHops}`,
    '- Scope: classical software simulation; no quantum hardware or physical quantum channel.',
    '- Reproducibility: the seed fixes the QKD transmission/sifting stream; the classical CHSH diagnostic uses separate randomness and is not physical certification.',
    '',
    '| Scenario | Eve intercepts | Measured QBER | Dynamic threshold | Mismatches / n | P(X ≥ k \u007c threshold) | Statistical inference | QKD verdict | CHSH sample |',
    '| --- | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |',
    ...rows,
    '',
    'The exact tail p-value is P(X ≥ k) under the honest-channel binomial model at that sample’s dynamic decision threshold. A small value means this mismatch count is unlikely under that model; a high value means this sample does not reject it, not proof of security. It is not the probability that an attack occurred. A CHSH result is an independent sampled diagnostic, not hardware certification.',
    'The seeded QKD privacy-amplification demo uses a reproducibility seed, so it makes no LHL privacy claim; the reported epsilon is null on that path. This receipt contains run metadata and measured outcomes only; it excludes document contents and derived key material.',
    '',
  ].join('\n')
}

function RunEvidenceReceipt({
  receipt,
  onJump,
}: {
  receipt: RunEvidenceReceipt
  onJump: (id: SectionId) => void
}) {
  const [copyStatus, setCopyStatus] = useState<'idle' | 'copied' | 'unavailable'>('idle')
  const clean = receipt.results.find((result) => result.scenario === 'secure')
  const attacked = receipt.results.find((result) => result.scenario === 'attack')
  const comparisonPassed = Boolean(clean?.is_authentic && clean.key_distilled && attacked && !attacked.is_authentic)

  const downloadReceipt = () => {
    const url = URL.createObjectURL(new Blob([runReceiptMarkdown(receipt)], { type: 'text/markdown;charset=utf-8' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `signiq-run-receipt-${receipt.seed}.md`
    link.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  const copyReceipt = async () => {
    if (!navigator.clipboard?.writeText) {
      setCopyStatus('unavailable')
      return
    }
    try {
      await navigator.clipboard.writeText(runReceiptMarkdown(receipt))
      setCopyStatus('copied')
    } catch {
      setCopyStatus('unavailable')
    }
  }

  return (
    <section className="panel run-evidence-receipt" aria-live="polite">
      <div className="panel-title-row">
        <div className="panel-title">Reproducible run receipt</div>
        <span className={`chip ${comparisonPassed ? 'chip-green' : 'chip-amber'}`}>
          {comparisonPassed ? '✓ clean key distilled · attack line exceeded' : 'review measured outcomes'}
        </span>
      </div>
      <div className="proof-receipt-meta">
        <span>run #{receipt.runId}</span>
        <span>seed {receipt.seed}</span>
        <span>{receipt.keyLength.toLocaleString()} qubits</span>
        <span>{new Date(receipt.completedAt).toLocaleString()}</span>
      </div>
      <div className="proof-scenario-grid">
        {receipt.results.map((result) => {
          const bounds = result.statistical_bounds
          const mismatches = bounds?.interval.k ?? Math.round(result.qber * result.matching_bases_count)
          const tone = result.is_authentic ? 'proof-channel-clean' : 'proof-channel-flagged'
          return (
            <article className={`proof-scenario ${tone}`} key={result.scenario}>
              <div className="proof-scenario-head">
                <h3>{SCENARIO_LABELS[result.scenario] ?? result.scenario}</h3>
                <span className={`chip ${result.is_authentic ? 'chip-green' : 'chip-red'}`}>
                  {result.is_authentic ? 'accepted' : 'threat flagged'}
                </span>
              </div>
              <div className="proof-qber">{(result.qber * 100).toFixed(2)}<small>% QBER</small></div>
              <div className="proof-evidence-grid">
                <div><span>Intercepted</span><b>{(result.intercept_ratio * 100).toFixed(0)}%</b></div>
                <div><span>Decision line</span><b>{(result.dynamic_threshold * 100).toFixed(2)}%</b></div>
                <div><span>Observed errors</span><b>{mismatches.toLocaleString()} / {result.matching_bases_count.toLocaleString()}</b></div>
                <div><span>Tail p (threshold model)</span><b>{formatTailProbability(bounds?.verdict.p_value)}</b></div>
                <div><span>Statistical inference</span><b>{result.is_authentic ? 'compatible with tested threshold' : bounds?.verdict.band ?? 'not reported'}</b></div>
                <div><span>CHSH sample</span><b>{result.bell_test ? `S = ${result.bell_test.s.toFixed(3)} · ${result.bell_test.certified ? 'violation' : 'no violation'}` : 'not reported'}</b></div>
              </div>
            </article>
          )
        })}
      </div>
      <p className="proof-receipt-note">
        Simulation evidence, not a hardware claim. The exact tail p-value is P(X ≥ k) under the honest-channel binomial model at that sample’s dynamic decision threshold: a small value means this mismatch count is unlikely under that model; a high value means it is not rejected on this sample, not proof of security. It is not the probability that an attack occurred. The receipt excludes file contents and key material.
      </p>
      <div className="proof-receipt-actions">
        <button className="btn btn-primary btn-sm" onClick={downloadReceipt}>Download evidence receipt</button>
        <button className="btn btn-sm" onClick={copyReceipt}>
          {copyStatus === 'copied' ? 'Receipt copied ✓' : copyStatus === 'unavailable' ? 'Clipboard unavailable' : 'Copy receipt'}
        </button>
        <span className="proof-next-label">Explore next:</span>
        <button className="link-btn" onClick={() => onJump('consensus')}>statistical bounds</button>
        <button className="link-btn" onClick={() => onJump('qds')}>signature lab</button>
        <button className="link-btn" onClick={() => onJump('ledger')}>audit ledger</button>
      </div>
    </section>
  )
}

/** Folio — the editorial section opener: italic folio number, small-caps 
 *  label, Fraunces title, and a running hairline. Sections stop being
 *  identical stacked cards and start reading like chapters. */
function Folio({
  no,
  label,
  title,
  note,
}: {
  no: string
  label: string
  title: React.ReactNode
  note?: React.ReactNode
}) {
  return (
    <div className="folio">
      <div className="folio-no">{no}</div>
      <div className="folio-main">
        <div className="folio-label">{label}</div>
        <h2 className="folio-title">{title}</h2>
      </div>
      <div className="folio-rule" aria-hidden />
      {note && <div className="folio-note">{note}</div>}
    </div>
  )
}

export default function App() {
  const [authUser, setAuthUser] = useState<string | null>(() => getAuthUsername())
  const [authRevision, setAuthRevision] = useState(0)
  const handleAuthChange = useCallback((user: string | null) => {
    setAuthUser(user)
    setAuthRevision((revision) => revision + 1)
  }, [])

  // --- experiment parameters ---
  const [teamOpen, setTeamOpen] = useState(false)
  const [keyLength, setKeyLength] = useState(20000)
  const [threshold, setThreshold] = useState(0.15)
  const [customMode, setCustomMode] = useState(false)
  const [eveRatio, setEveRatio] = useState(0.3)
  const [noiseRate, setNoiseRate] = useState(0.0)
  const [relayHops, setRelayHops] = useState(0)
  const [paceMs, setPaceMs] = useState(6)
  const [seed, setSeed] = useState('')
  const [lastSeed, setLastSeed] = useState<number | null>(null)
  const [message, setMessage] = useState('A sample message for the SigniQ simulation.')

  // --- run state ---
  const [running, setRunning] = useState(false)
  const [results, setResults] = useState<ScenarioResult[]>([])
  const {
    live,
    enqueue: enqueueLiveProgress,
    flush: flushLiveProgress,
    reset: resetLiveProgress,
  } = useThrottledRunProgress()
  const [log, setLog] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [backendUp, setBackendUp] = useState<boolean | null>(null)

  // --- sweep state ---
  const [sweepLoading, setSweepLoading] = useState(false)
  const [sweep, setSweep] = useState<{ ratio: number; qber: number; threshold: number; theory: number }[]>([])
  const [runReceipt, setRunReceipt] = useState<RunEvidenceReceipt | null>(null)
  const [noiseStudyLoading, setNoiseStudyLoading] = useState(false)
  const [noiseStudyData, setNoiseStudyData] = useState<NoiseEveCondition[]>([])
  const [noiseStudySeed, setNoiseStudySeed] = useState<number | null>(null)
  const [noiseStudyKeyLength, setNoiseStudyKeyLength] = useState<number | null>(null)
  const [guidedRunStep, setGuidedRunStep] = useState<number | null>(null)

  const acceptingRef = useRef(false)
  const runIdRef = useRef<number | null>(null)

  // Active nav section: driven by scroll position (IntersectionObserver) so
  // the rail highlights whatever the user is actually looking at, and by
  // click (smooth-scroll to the section).
  const [activeSection, setActiveSection] = useState<SectionId>('channel')
  const sectionNavRef = useRef<HTMLElement | null>(null)
  const suppressScrollSpyRef = useRef(false)
  const scrollSpyReleaseTimerRef = useRef<ReturnType<typeof window.setTimeout> | null>(null)

  useEffect(() => () => {
    if (scrollSpyReleaseTimerRef.current !== null) {
      window.clearTimeout(scrollSpyReleaseTimerRef.current)
    }
  }, [])

  useEffect(() => {
    const nav = sectionNavRef.current
    const activeTab = nav?.querySelector<HTMLButtonElement>(`[data-section="${activeSection}"]`)
    if (!nav || !activeTab) return

    // Compare viewport rectangles: offsetLeft is relative to the sticky header,
    // not this horizontally scrollable nav, so it drifts on narrow screens.
    const navRect = nav.getBoundingClientRect()
    const tabRect = activeTab.getBoundingClientRect()
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const behavior = reducedMotion ? 'auto' : 'smooth'
    if (tabRect.left < navRect.left + 8) {
      nav.scrollBy({ left: tabRect.left - navRect.left - 8, behavior })
    } else if (tabRect.right > navRect.right - 8) {
      nav.scrollBy({ left: tabRect.right - navRect.right + 8, behavior })
    }
  }, [activeSection])

  const pushLog = useCallback((line: string) => {
    const ts = new Date().toLocaleTimeString()
    setLog((prev) => [`${ts}  ${line}`, ...prev].slice(0, 8))
  }, [])

  useRunStream((ev: RunEvent) => {
    if (!acceptingRef.current) return
    if (runIdRef.current !== null && ev.run_id !== runIdRef.current) return

    if (ev.type === 'progress') {
      enqueueLiveProgress(ev)
    } else if (ev.type === 'result') {
      const label = SCENARIO_LABELS[ev.result.scenario] ?? ev.result.scenario
      const verdict = ev.result.is_authentic
        ? `AUTHENTIC (QBER ${(ev.result.qber * 100).toFixed(2)}%)`
        : `THREAT FLAGGED (QBER ${(ev.result.qber * 100).toFixed(2)}% > ${(ev.result.dynamic_threshold * 100).toFixed(2)}%)`
      pushLog(`${label}: ${verdict}`)
    } else if (ev.type === 'done') {
      flushLiveProgress()
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

  const handleRun = async (mode: 'current' | 'comparison' = 'current') => {
    const config = mode === 'comparison'
      ? {
          keyLength: REPRODUCIBLE_RUN_PRESET.keyLength,
          threshold: REPRODUCIBLE_RUN_PRESET.threshold,
          customMode: false,
          eveRatio: REPRODUCIBLE_RUN_PRESET.eveRatio,
          noiseRate: REPRODUCIBLE_RUN_PRESET.noiseRate,
          relayHops: REPRODUCIBLE_RUN_PRESET.relayHops,
          paceMs: REPRODUCIBLE_RUN_PRESET.paceMs,
          seed: REPRODUCIBLE_RUN_PRESET.seed,
          message: REPRODUCIBLE_RUN_PRESET.message,
        }
      : { keyLength, threshold, customMode, eveRatio, noiseRate, relayHops, paceMs, seed: parseSeed(), message }

    if (mode === 'comparison') {
      setKeyLength(config.keyLength)
      setThreshold(config.threshold)
      setCustomMode(false)
      setEveRatio(config.eveRatio)
      setNoiseRate(config.noiseRate)
      setRelayHops(config.relayHops)
      setPaceMs(config.paceMs)
      setSeed(String(config.seed))
      setMessage(config.message)
    }
    setError(null)
    setResults([])
    setRunReceipt(null)
    resetLiveProgress()
    setRunning(true)
    acceptingRef.current = true
    runIdRef.current = null
    try {
      const resp = await startRun({
        key_length: config.keyLength,
        base_threshold: config.threshold,
        intercept_ratio: config.customMode ? config.eveRatio : undefined,
        noise_rate: config.noiseRate > 0 ? config.noiseRate : undefined,
        relay_hops: config.relayHops > 0 ? config.relayHops : undefined,
        message: config.message || undefined,
        pace_ms: config.paceMs,
        seed: config.seed,
      })
      runIdRef.current = resp.run_id
      setResults(resp.results)
      const usedSeed = resp.seed ?? config.seed
      const established = resp.results.filter((r) => r.key_distilled).length
      pushLog(
        `Run #${resp.run_id}: ${established}/${resp.results.length} scenarios distilled a key · ` +
          `${describeSeed(usedSeed)} · ${config.keyLength.toLocaleString()} qubits · ` +
          `threshold ${(config.threshold * 100).toFixed(0)}%`,
      )
      if (mode === 'comparison') {
        setRunReceipt({
          runId: resp.run_id,
          seed: usedSeed ?? REPRODUCIBLE_RUN_PRESET.seed,
          completedAt: new Date().toISOString(),
          keyLength: config.keyLength,
          threshold: config.threshold,
          noiseRate: config.noiseRate,
          relayHops: config.relayHops,
          results: resp.results,
        })
      }
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

  const handleNoiseStudy = async () => {
    const studyKeyLength = 12_000
    const studySeed = parseSeed() ?? Math.floor(Math.random() * 2_000_000_000)
    const runCondition = (noise: number, intercept: number) => runSweep({
      intercept_ratios: [intercept],
      key_length: studyKeyLength,
      base_threshold: 0.15,
      noise_rate: noise,
      relay_hops: 0,
      seed: studySeed,
    })

    setNoiseStudyLoading(true)
    setNoiseStudyData([])
    setNoiseStudySeed(null)
    setNoiseStudyKeyLength(null)
    setError(null)
    try {
      const [cleanRun, noiseRun, eveRun, combinedRun] = await Promise.all([
        runCondition(0, 0),
        runCondition(0.08, 0),
        runCondition(0, 0.7),
        runCondition(0.08, 0.7),
      ])
      const conditions: NoiseEveCondition[] = [
        {
          id: 'clean',
          label: 'Clean',
          description: '0% noise · 0% intercept',
          result: cleanRun.sweep[0],
        },
        {
          id: 'noise',
          label: 'Noise only',
          description: '8% noise · 0% intercept',
          result: noiseRun.sweep[0],
        },
        {
          id: 'eve',
          label: 'Eve only',
          description: '0% noise · 70% intercept',
          result: eveRun.sweep[0],
        },
        {
          id: 'combined',
          label: 'Noise + Eve',
          description: '8% noise · 70% intercept',
          result: combinedRun.sweep[0],
        },
      ]
      setNoiseStudyData(conditions)
      setNoiseStudySeed(cleanRun.seed ?? studySeed)
      setNoiseStudyKeyLength(studyKeyLength)
      setLastSeed(cleanRun.seed ?? studySeed)
      pushLog(
        `Noise vs Eve 2×2: clean ${(conditions[0].result.qber * 100).toFixed(2)}% · ` +
          `noise ${(conditions[1].result.qber * 100).toFixed(2)}% · ` +
          `Eve ${(conditions[2].result.qber * 100).toFixed(2)}% · ` +
          `combined ${(conditions[3].result.qber * 100).toFixed(2)}% · seed ${cleanRun.seed ?? studySeed}`,
      )
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setNoiseStudyLoading(false)
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
    if (scrollSpyReleaseTimerRef.current !== null) {
      window.clearTimeout(scrollSpyReleaseTimerRef.current)
    }
    document.getElementById(id)?.scrollIntoView({
      behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',
      block: 'start',
    })
    scrollSpyReleaseTimerRef.current = window.setTimeout(() => {
      suppressScrollSpyRef.current = false
      scrollSpyReleaseTimerRef.current = null
    }, 1200)
    window.setTimeout(() => {
      const nav = sectionNavRef.current
      const activeTab = nav?.querySelector<HTMLButtonElement>(`[data-section="${id}"]`)
      if (!nav || !activeTab) return
      const navRect = nav.getBoundingClientRect()
      const tabRect = activeTab.getBoundingClientRect()
      const behavior = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'
      if (tabRect.left < navRect.left + 8) nav.scrollBy({ left: tabRect.left - navRect.left - 8, behavior })
      else if (tabRect.right > navRect.right - 8) nav.scrollBy({ left: tabRect.right - navRect.right + 8, behavior })
    }, 0)
  }

  const startGuidedRun = () => {
    setGuidedRunStep(0)
    jumpTo(GUIDED_RUN_STEPS[0].target)
  }

  const advanceGuidedRun = (direction: -1 | 1) => {
    if (guidedRunStep === null) return
    const next = guidedRunStep + direction
    if (next < 0) return
    if (next >= GUIDED_RUN_STEPS.length) {
      setGuidedRunStep(null)
      return
    }
    setGuidedRunStep(next)
    jumpTo(GUIDED_RUN_STEPS[next].target)
  }

  const runGuidedRunAction = (action: GuidedRunAction) => {
    if (action === 'comparison') {
      void handleRun('comparison')
      jumpTo('channel')
    } else {
      void handleNoiseStudy()
      jumpTo('noise-study')
    }
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

      {/* ---- team dossier ---- */}
      <TeamDossier open={teamOpen} onClose={() => setTeamOpen(false)} />

      {/* ---- fixed background: quantum lattice canvas + nebula wash ---- */}
      {entryDone && <QuantumBackdrop running={running} />}

      {/* ---- quiet atmosphere: static grain + vignette (no animation) ---- */}
      <div className="atmo-noise" aria-hidden />
      <div className="atmo-vignette" aria-hidden />

      {guidedRunStep !== null && (
        <GuidedRun
          stepIndex={guidedRunStep}
          onClose={() => setGuidedRunStep(null)}
          onNext={() => advanceGuidedRun(1)}
          onPrevious={() => advanceGuidedRun(-1)}
          onJump={jumpTo}
          onAction={runGuidedRunAction}
          actionBusy={running || noiseStudyLoading || sweepLoading || backendUp === false}
        />
      )}

      <header className="topbar">
        <div className="topbar-inner">
          <div className="topbar-primary">
            <div className="brand">
              <span className="brand-mark" aria-hidden="true">
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
            <div className="topbar-right">
              <span
                className={`pill ${backendUp === null ? 'pill-gray' : backendUp ? 'pill-green' : 'pill-red'}`}
                title={backendUp ? 'API reachable' : 'API unreachable'}
                role="status"
                aria-live="polite"
              >
                <span className="pill-dot" aria-hidden="true" /> {backendUp === null ? 'checking' : backendUp ? 'API online' : 'API offline'}
              </span>
              <button className="btn btn-primary" onClick={() => { void handleRun() }} disabled={running || backendUp === false}>
                {running ? 'Running…' : customMode ? 'Run custom experiment' : 'Run experiment'}
              </button>
            </div>
          </div>
          <nav className="section-nav" aria-label="Dashboard sections" ref={sectionNavRef}>
            {SECTIONS.map((s) => (
              <button
                key={s.id}
                className={`nav-tab ${activeSection === s.id ? 'nav-tab-active' : ''}`}
                data-section={s.id}
                aria-current={activeSection === s.id ? 'location' : undefined}
                onClick={() => jumpTo(s.id)}
              >
                {s.label}
              </button>
            ))}
          </nav>
        </div>
      </header>

      <AuthBar onLog={pushLog} onUserChange={handleAuthChange} />

      {error && <div className="error-banner">{error}</div>}

      {/* ---- hero: the archive plate — asymmetric, with a live stat ledger ---- */}
      <section className="hero" aria-label="Project introduction">
        <div className="hero-copy">
          <div className="hero-eyebrow">SIH26141 · SigniQ research prototype</div>
          <h2 className="hero-title">
            Documents sealed by <span className="hero-accent">measured evidence</span>, not
            black-box claims.
          </h2>
          <p className="hero-sub">
            SigniQ models six-state QKD and teleportation-based QDS, seals file bytes with
            AES-256-GCM, and records actions in a Merkle audit chain. The quantum protocol runs
            in a classical software simulator — not on quantum hardware or a physical channel.
            Inspect each measured verdict, attack and statistical bound live.
          </p>
          <div className="hero-foot">
            <div className="hero-badges">
              <span className="chip chip-blue">Six-State QKD</span>
              <span className="chip chip-violet">Teleportation QDS</span>
              <span className="chip chip-green">AES-256-GCM</span>
              <span className="chip chip-gray">Merkle ledger</span>
              <span className="chip chip-gray">P2P + relay</span>
            </div>
            <div className="run-evidence-prompt">
              <div className="run-evidence-mark" aria-hidden>↗</div>
              <div className="run-evidence-copy">
                <span className="run-evidence-kicker">Start here</span>
                <b>One seeded run. Two measured outcomes.</b>
                <span>20,000 qubits · clean channel vs. intercept-resend · independent CHSH sample</span>
              </div>
              <div className="run-evidence-controls">
                <button
                  className="btn btn-primary"
                  onClick={() => { void handleRun('comparison'); jumpTo('channel') }}
                  disabled={running || backendUp === false}
                  aria-label="Run the reproducible 20,000-qubit clean and intercept-resend comparison"
                >
                  {running ? 'Experiment running…' : 'Run comparison →'}
                </button>
                <button className="btn btn-sm" onClick={startGuidedRun}>
                  Guided run
                </button>
              </div>
            </div>
            <TeamFlame onOpen={() => setTeamOpen(true)} />
          </div>
        </div>
        <div className="hero-side" aria-label="Prototype statistics">
          <span className="hero-sec-mark">№ 26141</span>
          <div className="stat-grid">
            <div className="stat-line">
              <span className="stat-name">Protocol</span>
              <span className="stat-num">Six-State</span>
            </div>
            <div className="stat-line">
              <span className="stat-name">Signature</span>
              <span className="stat-num">Teleport QDS</span>
            </div>
            <div className="stat-line">
              <span className="stat-name">Cipher</span>
              <span className="stat-num">AES-256-GCM</span>
            </div>
            <div className="stat-line">
              <span className="stat-name">Integrity</span>
              <span className="stat-num">Merkle</span>
            </div>
            <div className="stat-line">
              <span className="stat-name">QDS model P(forge)</span>
              <span className="stat-num">4⁻qλ</span>
            </div>
            <div className="stat-line">
              <span className="stat-name">Threat decision</span>
              <span className="stat-num" style={{ color: 'var(--accent2)' }}>statistical</span>
            </div>
          </div>
        </div>
      </section>

      <Folio
        no="I"
        label="The Channel"
        title={<>Experiment <em>parameters</em></>}
        note={
          <>Set the qubit budget, QBER decision line, modeled fiber noise and relay hops — then
          compare a clean run with a simulated intercept-resend condition.</>
        }
      />
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
              style={sliderFillStyle(1000, 100000, keyLength)}
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
              style={sliderFillStyle(0, 0.5, threshold)}
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
              style={sliderFillStyle(0, 20, paceMs)}
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
              style={sliderFillStyle(0, 0.12, noiseRate)}
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
              style={sliderFillStyle(0, 4, relayHops)}
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
                style={sliderFillStyle(0, 1, eveRatio)}
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
      {runReceipt && <RunEvidenceReceipt receipt={runReceipt} onJump={jumpTo} />}

      <LiveMonitor live={live} log={log} running={running} baseThreshold={threshold} />

      <SweepPanel data={sweep} loading={sweepLoading} onRun={handleSweep} />

      <Folio
        no="I½"
        label="Controlled study"
        title={<>Noise against <em>Eve</em></>}
        note={<>Hold the simulator seed, key budget and detector fixed; change the environmental bit-flip rate and intercept-resend strategy independently.</>}
      />
      <NoiseVsEvePanel
        data={noiseStudyData}
        loading={noiseStudyLoading}
        seed={noiseStudySeed}
        keyLength={noiseStudyKeyLength}
        onRun={() => { void handleNoiseStudy() }}
      />

      <Folio
        no="I¾"
        label="The blind room"
        title={<>Diagnose the <em>unknown</em></>}
        note={<>The treatment stays hidden while you inspect measured evidence. Commit to a diagnosis before the reveal.</>}
      />
      <BlindChallenge onLog={pushLog} />

      <Folio
        no="II"
        label="The Vault"
        title={<>Seal, verify, <em>unlock</em></>}
        note={
          <>A file goes in; an opaque <b>.qsig</b> container comes out — ciphertext, not text.
          Verify plays the verifier; unlock recovers the original bytes. Optionally split the
          key across officer accounts (Shamir k-of-m).</>
        }
      />
      <div id="vault" className="section-anchor">          <DocVault onLog={pushLog} authUser={authUser} authRevision={authRevision} />
      </div>

      <Folio
        no="III"
        label="The Wire"
        title={<>Transfer <em>portal</em></>}
        note={
          <>Watch a document cross simulated relays: sifting, privacy amplification, HMAC,
          transmit, verify — every stage streamed live, every interception counted.</>
        }
      />
      <div id="transfer" className="section-anchor">
        <TransferPortal onLog={pushLog} />
      </div>

      <Folio
        no="IV"
        label="The Peers"
        title={<>Laptop to <em>laptop</em></>}
        note={
          <>Send a sealed container to another user account on this server, or across machines
          by address — same LAN or across the internet via the relay. Inbox holds what you
          received; outbox holds what you sent.</>
        }
      />
      <div id="p2p" className="section-anchor">
        <PeerTransfer onLog={pushLog} authUser={authUser} authRevision={authRevision} />
      </div>

      <Folio
        no="V"
        label="The Adversary"
        title={<>Attack <em>laboratory</em></>}
        note={
          <>An attacker captures a container, modifies it four ways and forwards it — the
          recipient’s verification rejects it with the failed check and a corresponding audit entry.</>
        }
      />
      <div id="attacks" className="section-anchor">
        <AttackLab onLog={pushLog} />
      </div>

      <Folio
        no="VI"
        label="The Signature"
        title={<>QDS <em>signature lab</em></>}
        note={
          <>The raw quantum digital signature, isolated: derive keys from six-state qubits,
          sign by teleportation, verify by measurement statistics, then watch forgeries fail.</>
        }
      />
      <div id="qds" className="section-anchor">
        <QdsLab />
      </div>

      <Folio
        no="VI½"
        label="The Consensus"
        title={<>Verification <em>ring</em> &amp; the bounds</>}
        note={
          <>Many receivers, one verdict: a k-of-m quorum over independent channels, and the
          Chernoff–Hoeffding engine that proves every threshold belongs to mathematics,
          not to taste.</>
        }
      />
      <div id="consensus" className="section-anchor">
        <ConsensusRing lastRun={results.length > 0 ? results : undefined} />
      </div>

      <Folio
        no="VII"
        label="The Record"
        title={<>Merkle audit <em>ledger</em></>}
        note={
          <>Every event above, hash-chained. The constellation plots the chain; the table keeps
          the receipts; inclusion proofs recompute the published root.</>
        }
      />
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
              {r.is_authentic ? (
                <div className="crypto-lines">
                  <div className="muted-line">
                    Session key established for this accepted channel; raw key material is intentionally withheld from the browser.
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
 * Fixed full-viewport backdrop: a van Gogh starry night over a Parrish
 * lapis sky. The sky itself (turbulent current + swirling nebula eddies)
 * is painted ONCE into an offscreen canvas and blitted each frame — the
 * per-frame work is a single drawImage plus a handful of cached-sprite
 * photons (twinkling stars, drifting entangled pairs). Quantum flair:
 * the two brightest "stars" are an entangled pair — their twin always
 * mirrors them across the canvas center.
 */
function QuantumBackdrop({ running }: { running: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const runningRef = useRef(running)
  runningRef.current = running

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let raf = 0
    let lastDraw = 0
    const motionPreference = window.matchMedia('(prefers-reduced-motion: reduce)')
    let reducedMotion = motionPreference.matches
    let width = window.innerWidth
    let height = window.innerHeight
    const dpr = Math.min(window.devicePixelRatio || 1, 1.75)
    const rand = (a: number, b: number) => a + Math.random() * (b - a)

    interface Star {
      x: number
      y: number
      r: number
      tone: 0 | 1 // 0 = golden ember, 1 = twilight violet
      phase: number
      speed: number
    }

    // ---- pre-rendered glow sprites (cheap drawImage per photon) ----
    const spriteFor = (rgb: string) => {
      const s = document.createElement('canvas')
      const R = 32
      s.width = s.height = R * 2
      const c = s.getContext('2d')
      if (c) {
        const g = c.createRadialGradient(R, R, 0, R, R, R)
        g.addColorStop(0, `rgba(${rgb}, 0.9)`)
        g.addColorStop(0.3, `rgba(${rgb}, 0.3)`)
        g.addColorStop(1, `rgba(${rgb}, 0)`)
        c.fillStyle = g
        c.fillRect(0, 0, R * 2, R * 2)
      }
      return s
    }
    const sprites = [spriteFor('201, 164, 92'), spriteFor('143, 176, 201')]

    // ---- the painted sky: composited once per resize ----
    let sky: HTMLCanvasElement | null = null
    const paintSky = () => {
      sky = document.createElement('canvas')
      sky.width = Math.max(2, Math.round(width / 2)) // half-res: buttery blur for free
      sky.height = Math.max(2, Math.round(height / 2))
      const s = sky.getContext('2d')
      if (!s) return
      const w = sky.width
      const h = sky.height

      // base: ink-night zenith -> indigo -> a breath of old gold at the horizon
      const base = s.createLinearGradient(0, 0, 0, h)
      base.addColorStop(0, '#04060c')
      base.addColorStop(0.45, '#070a12')
      base.addColorStop(0.8, '#0d1526')
      base.addColorStop(1, '#1a2036')
      s.fillStyle = base
      s.fillRect(0, 0, w, h)

      // swirling nebula eddies — van Gogh's curling sky, one arc per stroke
      const eddies = 14
      for (let i = 0; i < eddies; i++) {
        const cx = rand(0, w)
        const cy = rand(0, h * 0.72)
        const rad = rand(w * 0.08, w * 0.3)
        const hue = Math.random() < 0.55 ? '38, 52, 96' : '143, 176, 201'
        const glow = s.createRadialGradient(cx, cy, 0, cx, cy, rad)
        glow.addColorStop(0, `rgba(${hue}, 0.055)`)
        glow.addColorStop(1, 'rgba(0,0,0,0)')
        s.fillStyle = glow
        s.beginPath()
        s.arc(cx, cy, rad, 0, Math.PI * 2)
        s.fill()

        // the curl itself: a few fine spiral strokes in gold or violet —
        // kept faint so panels and forms read clearly on top of the sky
        const turns = rand(2.2, 4.2)
        const coils = 3
        for (let k = 0; k < coils; k++) {
          s.beginPath()
          s.strokeStyle = k % 2 ? `rgba(${hue}, 0.03)` : 'rgba(201, 164, 92, 0.026)'
          s.lineWidth = rand(0.6, 1.2)
          const off = rand(0, Math.PI * 2)
          for (let t = 0; t < turns * Math.PI * 2; t += 0.22) {
            const rr = (rad * 0.55 * t) / (turns * Math.PI * 2) + k * 1.5
            const x = cx + Math.cos(t + off + k) * rr
            const y = cy + Math.sin(t + off + k) * rr * 0.62 // elliptical: wind-blown
            if (t === 0) s.moveTo(x, y)
            else s.lineTo(x, y)
          }
          s.stroke()
        }
      }

      // a soft gold haze low on the horizon — the last light refusing to die
      const horizon = s.createLinearGradient(0, h * 0.72, 0, h)
      horizon.addColorStop(0, 'rgba(201, 164, 92, 0)')
      horizon.addColorStop(1, 'rgba(201, 164, 92, 0.06)')
      s.fillStyle = horizon
      s.fillRect(0, h * 0.72, w, h * 0.28)

      // fine grain, so the sky reads as canvas not screen
      for (let i = 0; i < (w * h) / 340; i++) {
        s.fillStyle = Math.random() < 0.5 ? 'rgba(236, 229, 212, 0.016)' : 'rgba(0, 0, 0, 0.05)'
        s.fillRect(rand(0, w), rand(0, h), 1, 1)
      }
    }

    const countFor = () => Math.max(20, Math.min(36, Math.round((width * height) / 52000)))
    const spawn = (): Star => ({
      x: rand(0, width),
      y: rand(0, height * 0.85),
      r: rand(0.7, 2.0),
      tone: Math.random() < 0.6 ? 0 : 1,
      phase: rand(0, Math.PI * 2),
      speed: rand(0.35, 1) * (Math.random() < 0.5 ? 1 : -1),
    })
    let stars: Star[] = []

    const resize = () => {
      width = window.innerWidth
      height = window.innerHeight
      canvas.width = Math.round(width * dpr)
      canvas.height = Math.round(height * dpr)
      canvas.style.width = `${width}px`
      canvas.style.height = `${height}px`
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      paintSky()
      const want = countFor()
      if (stars.length > want) stars.length = want
      while (stars.length < want) stars.push(spawn())
    }
    resize()
    window.addEventListener('resize', resize, { passive: true })

    // the entangled pair: two fixed "great stars", one gold one violet
    const twinA = { xF: 0.18, yF: 0.22, r: 3.1 }
    const twinB = { xF: 0.82, yF: 0.68, r: 2.4 }

    let last = performance.now()
    const frame = (now: number) => {
      if (document.hidden) {
        raf = 0
        return
      }
      if (!reducedMotion && now - lastDraw < 42) {
        raf = requestAnimationFrame(frame)
        return
      }
      const dt = Math.min((now - last) / 16.7, 3)
      last = now
      lastDraw = now
      ctx.clearRect(0, 0, width, height)
      if (sky) ctx.drawImage(sky, 0, 0, width, height)

      for (const star of stars) {
        if (!reducedMotion) {
          star.phase += 0.016 * dt * star.speed
          star.x += 0.03 * dt * star.speed * (runningRef.current ? 0.3 : 1)
        }
        if (star.x < -12) star.x = width + 12
        if (star.x > width + 12) star.x = -12
        const tw = 0.5 + 0.5 * Math.sin(star.phase)
        const spr = sprites[star.tone]
        const size = star.r * 7
        ctx.globalAlpha = 0.32 + 0.4 * tw
        ctx.drawImage(spr, star.x - size / 2, star.y - size / 2, size, size)
      }

      // the entangled pair — measuring one sets its twin (mirror position)
      const t = reducedMotion ? 0 : now / 1000
      const ax = twinA.xF * width + Math.sin(t * 0.21) * 20
      const ay = twinA.yF * height + Math.cos(t * 0.17) * 14
      const bx = width - ax
      const by = height - ay
      const twA = 0.62 + 0.38 * Math.sin(t * 1.1)
      const twB = 0.62 + 0.38 * Math.sin(t * 1.1 + Math.PI) // anti-correlated
      const sA = twinA.r * 8
      const sB = twinB.r * 8
      ctx.globalAlpha = 0.4 + 0.4 * twA
      ctx.drawImage(sprites[0], ax - sA / 2, ay - sA / 2, sA, sA)
      ctx.globalAlpha = 0.4 + 0.4 * twB
      ctx.drawImage(sprites[1], bx - sB / 2, by - sB / 2, sB, sB)
      ctx.globalAlpha = 1

      if (!reducedMotion) raf = requestAnimationFrame(frame)
    }
    raf = requestAnimationFrame(frame)
    const onVisibilityChange = () => {
      if (document.hidden) {
        cancelAnimationFrame(raf)
        raf = 0
      } else if (!reducedMotion && !raf) {
        last = performance.now()
        raf = requestAnimationFrame(frame)
      } else if (reducedMotion) {
        frame(performance.now())
      }
    }
    const onMotionPreferenceChange = (event: MediaQueryListEvent) => {
      reducedMotion = event.matches
      cancelAnimationFrame(raf)
      raf = 0
      if (document.hidden) return
      if (reducedMotion) {
        frame(performance.now())
      } else if (!raf) {
        last = performance.now()
        raf = requestAnimationFrame(frame)
      }
    }
    document.addEventListener('visibilitychange', onVisibilityChange)
    motionPreference.addEventListener('change', onMotionPreferenceChange)
    return () => {
      cancelAnimationFrame(raf)
      document.removeEventListener('visibilitychange', onVisibilityChange)
      motionPreference.removeEventListener('change', onMotionPreferenceChange)
      window.removeEventListener('resize', resize)
    }
  }, [])

  return <canvas ref={canvasRef} className="quantum-backdrop" aria-hidden />
}
