import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Entry sequence, take two — a quantum state prepares, drifts in
 * superposition, then COLLAPSES into the wordmark when you measure it
 * (click). No boot log, no borrowed CRT archive look.
 *
 * Structure:
 *   1. A Bloch-style sphere of orbiting qubits fades in over a faint
 *      interference pattern, with a "state not yet measured" caption.
 *   2. On click (or auto after ~7s): a radial measurement wave collapses
 *      every qubit to a single basis point, the sphere flashes into
 *      |1⟩, and the wordmark reveals underneath as the screen lifts.
 *
 * sessionStorage keeps it to once per tab session.
 */

const SEEN_KEY = 'signiq.entry.v4'

/** Bumped whenever the intro changes so returning visitors see it once
 *  again; App.tsx also reads this to know when to mount the backdrop. */
export const ENTRY_SEEN_KEY = SEEN_KEY

type Phase = 'superposition' | 'collapsing' | 'revealed'

export function EntrySequence({
  forceReplay = false,
  onFinished,
}: {
  forceReplay?: boolean
  /** Called once, when the sequence has fully lifted away. */
  onFinished?: () => void
}) {
  const [done, setDone] = useState(() => {
    if (forceReplay) return false
    try {
      return sessionStorage.getItem(SEEN_KEY) === '1'
    } catch {
      return false
    }
  })
  const [phase, setPhase] = useState<Phase>('superposition')
  const timers = useRef<number[]>([])

  const measure = useCallback(() => {
    setPhase((p) => {
      if (p !== 'superposition') return p
      timers.current.push(
        window.setTimeout(() => setPhase('revealed'), 900),
      )
      return 'collapsing'
    })
  }, [])

  // Synthetic keypresses (automation, browser autofill, screen-reader
  // tooling) must not skip the sequence — only genuine user input counts.
  const measureIfTrusted = useCallback(
    (e: { isTrusted?: boolean }) => {
      if (e.isTrusted === false) return
      measure()
    },
    [measure],
  )

  useEffect(() => {
    if (done) return
    timers.current.push(window.setTimeout(() => measure(), 7500))
    const onKey = (e: KeyboardEvent) => {
      if (e.isTrusted === false) return
      if (e.key === 'Escape' || e.key === 'Enter') measure()
    }
    window.addEventListener('keydown', onKey)
    return () => {
      timers.current.forEach(clearTimeout)
      timers.current = []
      window.removeEventListener('keydown', onKey)
    }
  }, [done, measure])

  useEffect(() => {
    if (phase !== 'revealed') return
    timers.current.push(
      window.setTimeout(() => {
        setDone(true)
        onFinished?.()
        // Revisit leaves the seen-flag alone when the user forced a replay,
        // so a normal reload still greets them — only the forced view skips it.
        if (!forceReplay) {
          try {
            sessionStorage.setItem(SEEN_KEY, '1')
          } catch {
            /* private mode — it just replays */
          }
        }
      }, 1100),
    )
  }, [phase, forceReplay, onFinished])

  if (done) return null

  return (
    <div
      className={`entry2 ${phase}`}
      onClick={measureIfTrusted}
      role="button"
      aria-label="Measure the state to enter"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter') measureIfTrusted(e)
      }}
    >
      <InterferenceCanvas phase={phase} />

      <div className="entry2-center">
        <div className="entry2-ket" aria-hidden>
          <span className="ket-a">|ψ⟩</span>
          <span className="ket-eq">=</span>
          <span className="ket-b">α|0⟩ + β|1⟩</span>
        </div>

        <QubitSphere phase={phase} />

        <div className="entry2-caption" aria-live="polite">
          {phase === 'superposition' && (
            <>
              <span className="cap-line">the state is in superposition</span>
              <span className="cap-dim">click to measure — measurement decides</span>
            </>
          )}
          {phase === 'collapsing' && <span className="cap-line cap-measure">measuring…</span>}
          {phase === 'revealed' && <span className="cap-line cap-collapsed">state collapsed: |1⟩</span>}
        </div>
      </div>

      <div className={`entry2-mark ${phase === 'revealed' ? 'entry2-mark-in' : ''}`} aria-hidden>
        <span className="entry2-name">SigniQ</span>
        <span className="entry2-tag">quantum-secured documents · team prometheus</span>
      </div>

      <span className="entry2-skip">measure to enter</span>
    </div>
  )
}

/** Slow-drifting qubit cloud around a wireframe sphere, on canvas. */
function QubitSphere({ phase }: { phase: Phase }) {
  const ref = useRef<HTMLCanvasElement | null>(null)

  useEffect(() => {
    const canvas = ref.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const size = 360
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    canvas.width = size * dpr
    canvas.height = size * dpr
    canvas.style.width = `${size}px`
    canvas.style.height = `${size}px`
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)

    const cx = size / 2
    const cy = size / 2
    const R = size * 0.36

    // Pre-rendered glow sprites (one per tone) — the old loop built a
    // radial gradient PER QUBIT PER FRAME; drawImage of a cached sprite
    // is an order of magnitude cheaper and looks the same.
    const spriteFor = (rgb: string) => {
      const s = document.createElement('canvas')
      const R2 = 24
      s.width = s.height = R2 * 2
      const c = s.getContext('2d')
      if (c) {
        const g = c.createRadialGradient(R2, R2, 0, R2, R2, R2)
        g.addColorStop(0, `rgba(${rgb}, 0.9)`)
        g.addColorStop(0.4, `rgba(${rgb}, 0.25)`)
        g.addColorStop(1, `rgba(${rgb}, 0)`)
        c.fillStyle = g
        c.fillRect(0, 0, R2 * 2, R2 * 2)
      }
      return s
    }
    const sprites: Record<string, HTMLCanvasElement> = {
      gold: spriteFor('217, 168, 81'),
      verdigris: spriteFor('143, 199, 168'),
    }

    // 24 qubits on randomized 3D orbits around the sphere.
    const qubits = Array.from({ length: 24 }, (_, i) => ({
      theta: (i / 24) * Math.PI * 2 + Math.random() * 0.5,
      phi: Math.acos(2 * Math.random() - 1),
      speed: 0.2 + Math.random() * 0.5,
      r: 3 + Math.random() * 5,
      tone: Math.random() < 0.75 ? 'gold' : 'verdigris',
    }))

    let raf = 0
    let t = 0

    const draw = () => {
      t += 0.016
      ctx.clearRect(0, 0, size, size)

      // wireframe sphere: 3 ellipses (equator + two meridians) + rim
      ctx.strokeStyle = 'rgba(217, 168, 81, 0.16)'
      ctx.lineWidth = 1
      ctx.beginPath()
      ctx.arc(cx, cy, R, 0, Math.PI * 2)
      ctx.stroke()
      ctx.setLineDash([3, 5])
      for (const squash of [0.35, 0.7]) {
        ctx.beginPath()
        ctx.ellipse(cx, cy, R, R * squash, 0, 0, Math.PI * 2)
        ctx.stroke()
        ctx.beginPath()
        ctx.ellipse(cx, cy, R * squash, R, 0, 0, Math.PI * 2)
        ctx.stroke()
      }
      // state axis |0⟩..|1⟩
      ctx.setLineDash([])
      ctx.strokeStyle = 'rgba(143, 199, 168, 0.32)'
      ctx.beginPath()
      ctx.moveTo(cx, cy - R * 1.18)
      ctx.lineTo(cx, cy + R * 1.18)
      ctx.stroke()
      ctx.fillStyle = 'rgba(143, 199, 168, 0.55)'
      ctx.font = '10px JetBrains Mono, monospace'
      ctx.textAlign = 'center'
      ctx.fillText('|0⟩', cx, cy - R * 1.18 - 8)
      ctx.fillText('|1⟩', cx, cy + R * 1.18 + 16)

      // qubits: project 3D orbit to 2D, depth-sort by z for size/alpha
      const pts = qubits.map((q) => {
        q.theta += 0.004 * q.speed
        q.phi += 0.002 * q.speed
        const x3 = R * 1.12 * Math.sin(q.phi) * Math.cos(q.theta)
        const y3 = R * 1.12 * Math.cos(q.phi)
        const z3 = R * 1.12 * Math.sin(q.phi) * Math.sin(q.theta)
        return { x: cx + x3, y: cy + y3, z: z3, q }
      })
      pts.sort((a, b) => a.z - b.z)
      for (const p of pts) {
        const depth = (p.z / (R * 1.12) + 1) / 2 // 0 back → 1 front
        const alpha = 0.15 + depth * 0.6
        const radius = p.q.r * (0.5 + depth * 0.9)
        const spr = sprites[p.q.tone]
        const glow = radius * 2.6
        ctx.globalAlpha = Math.min(1, alpha * 1.15)
        ctx.drawImage(spr, p.x - glow, p.y - glow, glow * 2, glow * 2)
      }
      ctx.globalAlpha = 1

      // collapse: qubits rapidly fall toward the |1⟩ pole
      if (phase !== 'superposition') {
        for (const q of qubits) {
          q.phi += (Math.PI - q.phi) * 0.14
          q.theta += 0.06
          q.r *= 0.94
        }
      }

      // Once revealed the sphere is animating out — stop the loop instead
      // of burning frames on an invisible canvas.
      if (phase === 'revealed') return
      raf = requestAnimationFrame(draw)
    }
    raf = requestAnimationFrame(draw)
    return () => cancelAnimationFrame(raf)
  }, [phase])

  return <canvas ref={ref} className="entry2-sphere" aria-hidden />
}

/**
 * Two-source interference pattern — what a quantum state "looks like"
 * before measurement. Rendered ONCE to an offscreen pattern, then drawn
 * statically (and faded/scaled during collapse) so this never costs
 * per-frame CPU.
 */
function InterferenceCanvas({ phase }: { phase: Phase }) {
  const ref = useRef<HTMLCanvasElement | null>(null)

  useEffect(() => {
    const canvas = ref.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5)
    const w = (canvas.width = Math.round(window.innerWidth * dpr))
    const h = (canvas.height = Math.round(window.innerHeight * dpr))
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)

    // draw once: two coherent sources + their interference fringes
    const s1 = { x: w * 0.38, y: h * 0.42 }
    const s2 = { x: w * 0.62, y: h * 0.58 }
    const img = ctx.createImageData(w, h)
    const d = img.data
    for (let y = 0; y < h; y += 1) {
      for (let x = 0; x < w; x += 1) {
        const d1 = Math.hypot(x - s1.x, y - s1.y)
        const d2 = Math.hypot(x - s2.x, y - s2.y)
        const interference = Math.cos((d1 - d2) * 0.055)
        const envelope = Math.exp(-((x - w / 2) ** 2 + (y - h / 2) ** 2) / (2 * (w / 3) ** 2))
        const v = Math.max(0, interference) * envelope
        if (v > 0.04) {
          const i = (y * w + x) * 4
          d[i] = 217 * v
          d[i + 1] = 168 * v
          d[i + 2] = 81 * v
          d[i + 3] = 46 * v
        }
      }
    }
    ctx.putImageData(img, 0, 0)
  }, [])

  return <canvas ref={ref} className={`entry2-fringes ${phase !== 'superposition' ? 'entry2-fringes-out' : ''}`} aria-hidden />
}
